#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <ngx_sha1.h>
#include <wslay/wslay.h>
#include "uthash.h"


struct ngx_http_ws_ctx_s {
    ngx_http_request_t *r;
    wslay_event_context_ptr ws;
    UT_hash_handle hh;
};

typedef struct ngx_http_ws_ctx_s ngx_http_ws_ctx_t;

ngx_http_ws_ctx_t *ws_ctx_hash = NULL;

struct ngx_http_ws_srv_addr_s {
    void *cscf; /** ngx_http_core_srv_conf_t **/
    ngx_str_t addr_text;
    UT_hash_handle hh;
};

typedef struct ngx_http_ws_srv_addr_s ngx_http_ws_srv_addr_t;

static ngx_http_ws_srv_addr_t *ws_srv_addr_hash = NULL;

static char *ngx_http_websocket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_websocket_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_websocket_process_init(ngx_cycle_t *cycle);

static ngx_command_t ngx_http_websocket_commands[] = {

    { ngx_string("websocket"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_websocket,
      0, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_websocket_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_websocket_module = {
    NGX_MODULE_V1,
    &ngx_http_websocket_module_ctx, /* module context */
    ngx_http_websocket_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    ngx_http_websocket_process_init,/* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

#define add_header(header_key, header_value)                                 \
    h = ngx_list_push(&r->headers_out.headers);                              \
    if (h == NULL) {                                                         \
        return NGX_ERROR;                                                    \
    }                                                                        \
    h->hash = 1;                                                             \
    h->key.len = sizeof(header_key) - 1;                                     \
    h->key.data = (u_char *) header_key;                                     \
    h->value.len = strlen((const char *)header_value);                       \
    h->value.data = (u_char *) header_value

#define WS_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

ngx_table_elt_t *ngx_http_websocket_find_key_header(ngx_http_request_t *r)
{
    ngx_table_elt_t *key_header = NULL;
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *headers = part->elts;
    for (ngx_uint_t i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            headers = part->elts;
            i = 0;
        }

        if (headers[i].hash == 0) {
            continue;
        }

        if (0 == ngx_strncmp(headers[i].key.data, (u_char *) "Sec-WebSocket-Key", headers[i].key.len)) {
            key_header = &headers[i];
        }
    }

    return key_header;
}

u_char *ngx_http_websocket_build_accept_key(ngx_table_elt_t *key_header, ngx_http_request_t *r)
{
    ngx_str_t encoded, decoded;
    ngx_sha1_t  sha1;
    u_char digest[20];

    decoded.len = sizeof(digest);
    decoded.data = digest;

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, key_header->value.data, key_header->value.len);
    ngx_sha1_update(&sha1, WS_UUID, sizeof(WS_UUID) - 1);
    ngx_sha1_final(digest, &sha1);

    encoded.len = ngx_base64_encoded_length(decoded.len) + 1;
    encoded.data = ngx_pnalloc(r->pool, encoded.len);
    ngx_memzero(encoded.data, encoded.len);
    if (encoded.data == NULL) {
        return NULL;
    }

    ngx_encode_base64(&encoded, &decoded);

    return encoded.data;
}

void
ngx_http_websocket_read(ngx_http_request_t *r)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http websocket test reading");

    n = recv(c->fd, buf, 1, MSG_PEEK);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http websocket readed %d bytes", n);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}

static ssize_t
recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
        int flags, void *user_data)
{
    ngx_http_request_t *r = (ngx_http_request_t *)user_data;
    ngx_connection_t  *c = r->connection;

    ssize_t n = recv(c->fd, buf, len, 0);
    if (n == -1) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    } else if (n == 0) {
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);

        n = -1;
    }

    return n;
}

static ssize_t
send_callback(wslay_event_context_ptr ctx,
        const uint8_t *data, size_t len, int flags, void *user_data)
{
    ngx_http_request_t *r = (ngx_http_request_t *)user_data;
    ngx_connection_t  *c = r->connection;

    ssize_t n = send(c->fd, data, len, 0);
    if (n == -1) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    }

    return n;
}

void
on_msg_recv_callback(wslay_event_context_ptr ctx,
        const struct wslay_event_on_msg_recv_arg *arg, void *user_data)
{
    ngx_http_request_t *r = (ngx_http_request_t *)user_data;

    if(!wslay_is_ctrl_frame(arg->opcode)) {
        struct wslay_event_msg msgarg = {
            arg->opcode, arg->msg, arg->msg_length
        };
        wslay_event_queue_msg(ctx, &msgarg);
    } else if (arg->opcode & WSLAY_CONNECTION_CLOSE) {
        ngx_http_ws_ctx_t *t;
        HASH_FIND_PTR(ws_ctx_hash, &r, t);

        if (t) {
            printf("%p\n", t);
            HASH_DEL(ws_ctx_hash, t);
        }

        r->count = 1;
        ngx_http_finalize_request(r, NGX_DONE);
    }
}

static ngx_int_t
ngx_http_websocket_process_init(ngx_cycle_t *cycle)
{
    int status;
    struct addrinfo hints = {};
    struct addrinfo *res, *p;
    char ipstr[33];
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char hostname[1024];
    hostname[1023] = '\0';
    gethostname(hostname, sizeof(hostname));

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "get ip: %s", gai_strerror(status));
    }

    ngx_http_ws_srv_addr_t *s;
    for (s = ws_srv_addr_hash; s != NULL; s = s->hh.next) {
        printf(">>>:%p\n", s->cscf);
        p = res;

        struct sockaddr_in *ip = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(p->ai_family, (void *)&ip->sin_addr, ipstr, sizeof(ipstr));

        int listen_fd = socket(PF_INET, SOCK_STREAM, 0);

        if (bind(listen_fd, (struct sockaddr *)ip, sizeof(struct sockaddr_in)) == -1) {
            return NGX_ABORT;
        }

        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(struct sockaddr_in);
        if (getsockname(listen_fd, (struct sockaddr *) &addr, &addr_len) == -1) {
            return NGX_ABORT;
        }
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "get ip: %s:%d", ipstr, ntohs(addr.sin_port));

        // ngx_conf_t
        ngx_conf_t conf;
        ngx_memzero(&conf, sizeof(ngx_conf_t));

        conf.temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, cycle->log);
        if (conf.temp_pool == NULL) {
            return NGX_ABORT;
        }

        conf.ctx = cycle->conf_ctx[ngx_http_module.index];
        conf.cycle = cycle;
        conf.pool = cycle->pool;
        conf.log = cycle->log;
        // lsopt
        ngx_http_listen_opt_t lsopt;
        ngx_memzero(&lsopt, sizeof(ngx_http_listen_opt_t));

        struct sockaddr_in *sin = &lsopt.sockaddr.sockaddr_in;
        *sin = addr;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = NGX_LISTEN_BACKLOG;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
        lsopt.wildcard = 0;

        (void) ngx_sock_ntop(&lsopt.sockaddr.sockaddr, lsopt.socklen,
                lsopt.addr, NGX_SOCKADDR_STRLEN, 1);

        if (ngx_http_add_listen(&conf, s->cscf, &lsopt) != NGX_OK) {
            return NGX_ABORT;
        }

        ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf((&conf), ngx_http_core_module);
        ngx_http_conf_port_t *port = cmcf->ports->elts;
        port += cmcf->ports->nelts - 1;
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "port %d", port->port);

        ngx_http_init_listening(&conf, port);
        ngx_listening_t *ls = cycle->listening.elts;
        ls += cycle->listening.nelts - 1;
        ls->fd = listen_fd;

        ngx_connection_t *c = ngx_get_connection(ls->fd, cycle->log);
        if (c == NULL) {
            return NGX_ERROR;
        }

        c->type = ls->type;
        c->log = &ls->log;

        c->listening = ls;
        ls->connection = c;

        ngx_event_t *rev = c->read;

        rev->log = c->log;
        rev->accept = 1;
        rev->handler = ngx_event_accept;
        printf(">>>%.*s\n", (int)ls->addr_text.len, ls->addr_text.data);
        s->addr_text = ls->addr_text;

        if (listen(ls->fd, NGX_LISTEN_BACKLOG) != 0) {
            return NGX_ERROR;
        }

        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        ngx_destroy_pool(conf.temp_pool);
    }

    freeaddrinfo(res);

    return NGX_OK;
}

static struct wslay_event_callbacks callbacks = {
    recv_callback,
    send_callback,
    NULL,
    NULL,
    NULL,
    NULL,
    on_msg_recv_callback
};

static void
ngx_http_ws_event_handler(ngx_http_request_t *r)
{
    ngx_connection_t *c = r->connection;
    wslay_event_context_ptr ctx = (wslay_event_context_ptr) r->upstream;

    if (c->read->ready) {
        wslay_event_recv(ctx);
    }

    if (c->write->ready) {
        wslay_event_send(ctx);
    }
}

static ngx_int_t ngx_http_websocket_handler(ngx_http_request_t *r)
{
    r->count++;
    r->keepalive = 0;

    ngx_table_elt_t* h;

    ngx_table_elt_t *key_header = ngx_http_websocket_find_key_header(r);

    if (key_header != NULL) {
        u_char *accept = ngx_http_websocket_build_accept_key(key_header, r);

        if (accept == NULL) {
            return NGX_ERROR;
        }

        add_header("Sec-WebSocket-Accept", accept);
    }
    /* ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "foo %d", key_header->value.len); */

    r->headers_out.status = NGX_HTTP_SWITCHING_PROTOCOLS;
    r->headers_out.status_line.data = (u_char *) "101 Switching Protocols";
    r->headers_out.status_line.len = sizeof("101 Switching Protocols") - 1;

    add_header("Upgrade", "websocket");
    add_header("Sec-WebSocket-Version", "13");

    wslay_event_context_ptr ctx = ngx_pnalloc(r->pool, sizeof(wslay_event_context_ptr));

    wslay_event_context_server_init(&ctx, &callbacks, r);

    r->read_event_handler = ngx_http_ws_event_handler;
    r->upstream = (ngx_http_upstream_t *) ctx;

    ngx_http_send_header(r);
    ngx_http_send_special(r, NGX_HTTP_FLUSH);

    ngx_http_ws_ctx_t *t = ngx_pnalloc(r->pool, sizeof(ngx_http_ws_ctx_t));
    t->r = r;
    t->ws = ctx;
    HASH_ADD_PTR(ws_ctx_hash, r, t);

    ngx_http_core_srv_conf_t *cscf = r->srv_conf[ngx_http_core_module.ctx_index];
    ngx_http_core_loc_conf_t *clcf = r->loc_conf[ngx_http_core_module.ctx_index];

    ngx_http_ws_srv_addr_t *push_addr;
    HASH_FIND_PTR(ws_srv_addr_hash, &cscf, push_addr);

    char msg_buf[256];
    int msg_buf_len = sprintf(msg_buf, "http://%p@%.*s%.*s", r,
            (int)push_addr->addr_text.len, push_addr->addr_text.data,
            (int)clcf->name.len, clcf->name.data);
    struct wslay_event_msg msgarg = {
        WSLAY_TEXT_FRAME, (uint8_t *)msg_buf, msg_buf_len
    };

    wslay_event_queue_msg(ctx, &msgarg);
    wslay_event_send(ctx);

    return NGX_OK;
}

static char *ngx_http_websocket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_core_srv_conf_t *cscf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_websocket_handler;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    ngx_http_ws_srv_addr_t *srv_addr = ngx_pnalloc(cf->pool, sizeof(ngx_http_ws_srv_addr_t));
    srv_addr->cscf = cscf;
    HASH_ADD_PTR(ws_srv_addr_hash, cscf, srv_addr);

    return NGX_CONF_OK;
}

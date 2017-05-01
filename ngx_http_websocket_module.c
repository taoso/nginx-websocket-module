#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <ngx_sha1.h>
#include <wslay/wslay.h>
#include "uthash.h"


struct ngx_http_ws_loc_conf_s {
    ngx_int_t pingintvl;
    ngx_int_t idleintvl;
};

struct ngx_http_ws_ctx_s {
    ngx_http_request_t *r;
    wslay_event_context_ptr ws;
    ngx_event_t *ping_ev;
    ngx_event_t *timeout_ev;
    ngx_int_t pingintvl;
    ngx_int_t idleintvl;
    UT_hash_handle hh;
};

struct ngx_http_ws_srv_addr_s {
    void *cscf; /** ngx_http_core_srv_conf_t **/
    struct addrinfo *addrs;
    int port;
    UT_hash_handle hh;
};

typedef struct ngx_http_ws_loc_conf_s ngx_http_ws_loc_conf_t;
typedef struct ngx_http_ws_ctx_s ngx_http_ws_ctx_t;
typedef struct ngx_http_ws_srv_addr_s ngx_http_ws_srv_addr_t;

static ngx_http_ws_ctx_t *ws_ctx_hash = NULL;
static ngx_http_ws_srv_addr_t *ws_srv_addr_hash = NULL;

static char *ngx_http_ws_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ws_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ws_process_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_ws_handshake(ngx_http_request_t *r);
static ngx_int_t ngx_http_ws_push(ngx_http_request_t *r);
static ngx_int_t ngx_http_ws_send_handshake(ngx_http_request_t *r);
static ngx_int_t ngx_http_ws_add_push_listen(ngx_cycle_t *cycle,
        ngx_http_ws_srv_addr_t *s, struct addrinfo *p);
static void ngx_http_ws_close(ngx_http_ws_ctx_t *t);
static void ngx_http_ws_add_timer(ngx_http_ws_ctx_t *t);
static void ngx_http_ws_send_push_token(ngx_http_ws_ctx_t *t);
static ngx_http_ws_ctx_t *ngx_http_ws_init_ctx(ngx_http_request_t *r);

static ngx_command_t ngx_http_websocket_commands[] = {

    { ngx_string("websocket"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_http_ws_conf,
      0, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL },

    ngx_null_command
};

void *
ngx_http_ws_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ws_loc_conf_t *lcf = ngx_palloc(cf->pool, sizeof(ngx_http_ws_loc_conf_t));
    lcf->pingintvl = 300 * 1000; // 5 min
    lcf->idleintvl = 360 * 1000; // 6 min

    return lcf;
}

static ngx_http_module_t ngx_http_websocket_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_ws_create_loc_conf, /* create location configuration */
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
    ngx_http_ws_process_init,       /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

#define ADD_HEADER(header_key, header_value)                                 \
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

static ngx_table_elt_t *
ngx_http_ws_find_key_header(ngx_http_request_t *r)
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

static u_char *
ngx_http_ws_build_accept_key(ngx_table_elt_t *key_header, ngx_http_request_t *r)
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

static ssize_t
ngx_http_ws_recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
        int flags, void *user_data)
{
    ngx_http_ws_ctx_t *t = user_data;
    ngx_http_request_t *r = t->r;
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
ngx_http_ws_send_callback(wslay_event_context_ptr ctx,
        const uint8_t *data, size_t len, int flags, void *user_data)
{
    ngx_http_ws_ctx_t *t = user_data;
    ngx_http_request_t *r = t->r;
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

static void
ngx_http_ws_flush_timer(ngx_http_ws_ctx_t *t)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
            "websocket: flush timer: %d", t->r->connection->fd);

    ngx_add_timer(t->ping_ev, t->pingintvl);
    ngx_add_timer(t->timeout_ev, t->idleintvl);
}

static void
ngx_http_ws_msg_callback(wslay_event_context_ptr ctx,
        const struct wslay_event_on_msg_recv_arg *arg, void *user_data)
{
    ngx_http_ws_ctx_t *t = user_data;

    ngx_http_ws_flush_timer(t);

    if(!wslay_is_ctrl_frame(arg->opcode)) {
        struct wslay_event_msg msg = {
            arg->opcode, arg->msg, arg->msg_length
        };
        wslay_event_queue_msg(ctx, &msg);
    } else if (arg->opcode == WSLAY_CONNECTION_CLOSE) {
        ngx_http_ws_close(t);
    }
}

static void
ngx_http_ws_close(ngx_http_ws_ctx_t *t)
{
    ngx_http_request_t *r = t->r;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
            "websocket: close %d %p", t->r->connection->fd, t->ws);

    /* FIXME the t has been overwrited */
    HASH_FIND_INT(ws_ctx_hash, &r->connection->fd, t);

    if (t) {
        HASH_DEL(ws_ctx_hash, t);
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
                "websocket: del ctx %d %p", t->r->connection->fd, t->ws);
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
            "websocket: clear timer %d %p", t->r->connection->fd, t->ws);

    if (t->ping_ev->timer_set) {
        ngx_del_timer(t->ping_ev);
    }
    if (t->timeout_ev->timer_set) {
        ngx_del_timer(t->timeout_ev);
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
            "websocket: finalize request %d %p", t->r->connection->fd, t->ws);
    r->count = 1;
    ngx_http_finalize_request(r, NGX_DONE);
}

static struct addrinfo *
ngx_http_ws_get_addrinfo(ngx_cycle_t *cycle)
{
    int status;
    struct addrinfo hints = {};
    struct addrinfo *res = NULL;

    hints.ai_family = AF_INET; /* TODO support IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char hostname[cycle->hostname.len + 1];
    hostname[cycle->hostname.len] = '\0';
    ngx_memcpy(hostname, cycle->hostname.data, cycle->hostname.len);

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "get ip: %s", gai_strerror(status));
    }

    return res;
}

static ngx_int_t
ngx_http_ws_process_init(ngx_cycle_t *cycle)
{
    struct addrinfo *res = ngx_http_ws_get_addrinfo(cycle);

    ngx_http_ws_srv_addr_t *s;
    for (s = ws_srv_addr_hash; s != NULL; s = s->hh.next) {
        ngx_int_t rc = ngx_http_ws_add_push_listen(cycle, s, res);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

static ngx_socket_t
ngx_http_ws_alloc_push_listenfd()
{
    struct sockaddr_in any;
    any.sin_family = AF_INET;
    any.sin_port = htons(0); /* let os choose port */
    any.sin_addr.s_addr = INADDR_ANY;

    ngx_socket_t listen_fd = socket(PF_INET, SOCK_STREAM, 0);

    if (bind(listen_fd, (struct sockaddr *)&any, sizeof(struct sockaddr_in)) == -1) {
        return 0;
    }

    if (listen(listen_fd, NGX_LISTEN_BACKLOG) != 0) {
        return 0;
    }

    return listen_fd;
}

static ngx_int_t
ngx_http_ws_init_ngx_conf(ngx_cycle_t *cycle, ngx_conf_t *conf)
{
    ngx_memzero(conf, sizeof(ngx_conf_t));

    conf->temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, cycle->log);
    if (conf->temp_pool == NULL) {
        return NGX_ABORT;
    }

    conf->ctx = cycle->conf_ctx[ngx_http_module.index];
    conf->cycle = cycle;
    conf->pool = cycle->pool;
    conf->log = cycle->log;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ws_init_lsopt(ngx_http_listen_opt_t *lsopt, ngx_socket_t listen_fd)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    if (getsockname(listen_fd, (struct sockaddr *) &addr, &addr_len) == -1) {
        return 0;
    }

    ngx_memzero(lsopt, sizeof(ngx_http_listen_opt_t));

    struct sockaddr_in *sin = &lsopt->sockaddr.sockaddr_in;
    ngx_memcpy(sin, &addr, addr_len);

    lsopt->socklen = sizeof(struct sockaddr_in);

    lsopt->backlog = NGX_LISTEN_BACKLOG;
    lsopt->rcvbuf = -1;
    lsopt->sndbuf = -1;
    lsopt->wildcard = 1;

    (void) ngx_sock_ntop(&lsopt->sockaddr.sockaddr, lsopt->socklen,
            lsopt->addr, NGX_SOCKADDR_STRLEN, 1);

    return ntohs(addr.sin_port);
}

static ngx_listening_t *
ngx_http_ws_add_listening(ngx_cycle_t *cycle, ngx_conf_t conf, ngx_socket_t fd)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf((&conf), ngx_http_core_module);
    ngx_http_conf_port_t *port = cmcf->ports->elts;
    port += cmcf->ports->nelts - 1;

    ngx_http_init_listening(&conf, port);
    ngx_listening_t *ls = cycle->listening.elts;
    ls += cycle->listening.nelts - 1;
    ls->fd = fd;

    return ls;
}

static ngx_int_t
ngx_http_ws_add_listen_event(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_connection_t *c = ngx_get_connection(ls->fd, cycle->log);
    if (c == NULL) {
        return NGX_ABORT;
    }

    c->type = ls->type;
    c->log = &ls->log;

    c->listening = ls;
    ls->connection = c;

    ngx_event_t *rev = c->read;

    rev->log = c->log;
    rev->accept = 1;
    rev->handler = ngx_event_accept;

    return ngx_add_event(rev, NGX_READ_EVENT, 0);
}

static ngx_int_t
ngx_http_ws_add_push_listen(ngx_cycle_t *cycle, ngx_http_ws_srv_addr_t *s,
        struct addrinfo *p)
{
    ngx_socket_t listen_fd = ngx_http_ws_alloc_push_listenfd();
    if (listen_fd == 0) {
        return NGX_ABORT;
    }

    ngx_conf_t conf, *cf;
    cf = &conf;
    if (ngx_http_ws_init_ngx_conf(cycle, &conf) != NGX_OK) {
        return NGX_ABORT;
    }

    ngx_http_listen_opt_t lsopt;
    ngx_int_t port = ngx_http_ws_init_lsopt(&lsopt, listen_fd);
    if (port == 0) {
        return NGX_ABORT;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "websocket: listen on port %d", port);

    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cmcf->ports = NULL; /* ports array has been freed by not reset to NULL
                           in master process. */

    if (ngx_http_add_listen(&conf, s->cscf, &lsopt) != NGX_OK) {
        return NGX_ABORT;
    }

    ngx_listening_t *ls = ngx_http_ws_add_listening(cycle, conf, listen_fd);

    s->addrs = p;
    s->port = port;

    ngx_int_t rc = ngx_http_ws_add_listen_event(cycle, ls);

    ngx_destroy_pool(conf.temp_pool);

    return rc;
}

static struct wslay_event_callbacks callbacks = {
    ngx_http_ws_recv_callback,
    ngx_http_ws_send_callback,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_ws_msg_callback
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

static ngx_int_t ngx_http_ws_handler(ngx_http_request_t *r)
{
    if (r->method & NGX_HTTP_GET) {
        return ngx_http_ws_handshake(r);
    } else if (r->method & NGX_HTTP_POST) {
        return ngx_http_ws_push(r);
    } else if (r->method & NGX_HTTP_OPTIONS) {
        /* TODO add allow methods */
        return NGX_HTTP_NO_CONTENT;
    } else {
        return NGX_HTTP_NOT_ALLOWED;
    }
}

static void
ngx_http_ws_push_body_handler(ngx_http_request_t *r)
{
    if (r->request_body == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* TODO iterate bufs */
    /* TODO process temp_file */
    ngx_buf_t *buf = r->request_body->bufs->buf;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "websocket: push %d %*s",
            r->connection->fd, (int)(buf->last - buf->pos), buf->pos);

    ngx_str_t user = r->headers_in.user;
    ngx_socket_t fd = (int) ngx_atoi((u_char *)user.data, (size_t)user.len);
    ngx_http_ws_ctx_t *t;
    HASH_FIND_INT(ws_ctx_hash, &fd, t);
    if (t == NULL) {
        return;
    }

    struct wslay_event_msg wsmsg = {
        /* TODO process binary data */
        WSLAY_TEXT_FRAME, buf->pos, buf->last - buf->pos
    };
    wslay_event_queue_msg(t->ws, &wsmsg);
    wslay_event_send(t->ws);

    ngx_http_finalize_request(r, NGX_HTTP_NO_CONTENT);
}

static ngx_int_t
ngx_http_ws_push(ngx_http_request_t *r)
{
    ngx_int_t rc = ngx_http_auth_basic_user(r);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t user = r->headers_in.user;
    if (user.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_socket_t fd = (int) ngx_atoi((u_char *)user.data, (size_t)user.len);
    ngx_http_ws_ctx_t *t;
    HASH_FIND_INT(ws_ctx_hash, &fd, t);
    if (t == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_ws_push_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static void
ngx_http_ws_ping(ngx_event_t *ev)
{
    ngx_http_ws_ctx_t *t = ev->data;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
            "websocket: ping %d %p", t->r->connection->fd, t->ws);

    struct wslay_event_msg msg = { WSLAY_PING, NULL, 0 };

    wslay_event_queue_msg(t->ws, &msg);
    wslay_event_send(t->ws);
}

static void
ngx_http_ws_timeout(ngx_event_t *ev)
{
    ngx_http_ws_ctx_t *t = ev->data;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, t->r->connection->log, 0,
            "websocket: timeout %d %p", t->r->connection->fd, t->ws);

    struct wslay_event_msg msg = { WSLAY_CONNECTION_CLOSE, NULL, 0 };

    wslay_event_queue_msg(t->ws, &msg);
    wslay_event_send(t->ws);

    ngx_http_ws_close(t);
}

static ngx_int_t
ngx_http_ws_handshake(ngx_http_request_t *r)
{
    r->count++; /* prevent nginx close connection after upgrade */
    r->keepalive = 0;

    ngx_http_ws_send_handshake(r); /* TODO check send error */

    ngx_http_ws_ctx_t *t = ngx_http_ws_init_ctx(r);

    ngx_http_ws_send_push_token(t);
    ngx_http_ws_add_timer(t);

    return NGX_OK;
}

static ngx_int_t
ngx_http_ws_send_handshake(ngx_http_request_t *r)
{
    ngx_table_elt_t* h;

    ngx_table_elt_t *key_header = ngx_http_ws_find_key_header(r);

    if (key_header != NULL) {
        u_char *accept = ngx_http_ws_build_accept_key(key_header, r);

        if (accept == NULL) {
            return NGX_ERROR;
        }

        ADD_HEADER("Sec-WebSocket-Accept", accept);
    }

    r->headers_out.status = NGX_HTTP_SWITCHING_PROTOCOLS;
    r->headers_out.status_line.data = (u_char *) "101 Switching Protocols";
    r->headers_out.status_line.len = sizeof("101 Switching Protocols") - 1;

    ADD_HEADER("Upgrade", "websocket");
    ADD_HEADER("Sec-WebSocket-Version", "13");

    ngx_http_send_header(r);

    return ngx_http_send_special(r, NGX_HTTP_FLUSH);
}

static ngx_http_ws_ctx_t *
ngx_http_ws_init_ctx(ngx_http_request_t *r)
{
    wslay_event_context_ptr ctx = NULL;
    ngx_http_ws_ctx_t *t = ngx_pnalloc(r->pool, sizeof(ngx_http_ws_ctx_t));
    t->r = r;

    ngx_http_ws_loc_conf_t *wlcf = r->loc_conf[ngx_http_websocket_module.ctx_index];

    t->pingintvl = wlcf->pingintvl;
    t->idleintvl = wlcf->idleintvl;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "websocket: pingintvl: %d, idleintvl: %d",
            t->pingintvl, t->idleintvl);

    wslay_event_context_server_init(&ctx, &callbacks, t);

    r->read_event_handler = ngx_http_ws_event_handler;
    r->upstream = (ngx_http_upstream_t *) ctx;

    t->ws = ctx;
    HASH_ADD_INT(ws_ctx_hash, r->connection->fd, t);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "websocket: new ctx: %d %p", r->connection->fd, t);

    return t;
}

static void
ngx_http_ws_send_push_token(ngx_http_ws_ctx_t *t)
{
    ngx_http_request_t *r = t->r;
    wslay_event_context_ptr ctx = t->ws;

    ngx_http_core_srv_conf_t *cscf = r->srv_conf[ngx_http_core_module.ctx_index];
    ngx_http_core_loc_conf_t *clcf = r->loc_conf[ngx_http_core_module.ctx_index];

    ngx_http_ws_srv_addr_t *push_addr;
    HASH_FIND_PTR(ws_srv_addr_hash, &cscf, push_addr);

    char token_buf[256], tokens_buf[4096], *bufp;
    bufp = tokens_buf;

    for (struct addrinfo *p = push_addr->addrs; p != NULL; p = p->ai_next) {
        void *addr;
        char ipstr[INET6_ADDRSTRLEN];
        struct sockaddr_in *ip = (struct sockaddr_in *)p->ai_addr;
        addr = &ip->sin_addr;
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        sprintf(token_buf, "http://%d@%s:%d%.*s",
                r->connection->fd, ipstr, push_addr->port,
                (int)clcf->name.len, clcf->name.data);

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "websocket: push token: %s", token_buf);
        bufp += sprintf(bufp, "%s,", token_buf);
    }

    struct wslay_event_msg msgarg = {
        WSLAY_TEXT_FRAME, (uint8_t *)tokens_buf, bufp - tokens_buf - 1
    };

    wslay_event_queue_msg(ctx, &msgarg);
    wslay_event_send(ctx);
}

static void
ngx_http_ws_add_timer(ngx_http_ws_ctx_t *t)
{
    ngx_event_t *ping_ev = ngx_pnalloc(t->r->pool, sizeof(ngx_event_t) * 2);
    ngx_event_t *timeout_ev = ping_ev++;

    ping_ev->data = t;
    ping_ev->log = t->r->connection->log;
    ping_ev->handler = ngx_http_ws_ping;

    timeout_ev->data = t;
    timeout_ev->log = t->r->connection->log;
    timeout_ev->handler = ngx_http_ws_timeout;

    t->ping_ev = ping_ev;
    t->timeout_ev = timeout_ev;

    ngx_http_ws_flush_timer(t);
}

static char *
ngx_http_ws_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_core_srv_conf_t *cscf;
    ngx_http_ws_loc_conf_t *wlcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ws_handler;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    ngx_http_ws_srv_addr_t *srv_addr = ngx_pnalloc(cf->pool, sizeof(ngx_http_ws_srv_addr_t));
    srv_addr->cscf = cscf;
    HASH_ADD_PTR(ws_srv_addr_hash, cscf, srv_addr);

    wlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_websocket_module);
    ngx_str_t *value = cf->args->elts;
    for (ngx_uint_t n = 1; n < cf->args->nelts; n++) {
        /* TODO ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ws:%V:%V", clcf->name, value[n]); */

        if (ngx_strncmp(value[n].data, "pingintvl=", 10) == 0) {
            wlcf->pingintvl = ngx_atoi(value[n].data + 10, value[n].len - 10);
        }

        if (ngx_strncmp(value[n].data, "idleintvl=", 10) == 0) {
            wlcf->idleintvl = ngx_atoi(value[n].data + 10, value[n].len - 10);
        }
    }

    return NGX_CONF_OK;
}

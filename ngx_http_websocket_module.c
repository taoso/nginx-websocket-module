#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <ngx_sha1.h>
#include <wslay/wslay.h>


struct ngx_http_ws_ctx_s {
    ngx_http_request_t *r;
    wslay_event_context_ptr *ws;
};

typedef struct ngx_http_ws_ctx_s ngx_http_ws_ctx_t;

static char *ngx_http_websocket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_websocket_handler(ngx_http_request_t *r);

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
    NULL,                           /* init process */
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
    if(n == -1) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
    } else if(n == 0) {
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
    if(n == -1) {
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
    if(!wslay_is_ctrl_frame(arg->opcode)) {
        struct wslay_event_msg msgarg = {
            arg->opcode, arg->msg, arg->msg_length
        };
        wslay_event_queue_msg(ctx, &msgarg);
    }
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
    r->main->count++;

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

    struct wslay_event_msg msgarg = {
        WSLAY_TEXT_FRAME, (uint8_t *)"hehe", 4
    };

    wslay_event_queue_msg(ctx, &msgarg);
    wslay_event_send(ctx);

    return NGX_OK;
}

static char *ngx_http_websocket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_websocket_handler;

    return NGX_CONF_OK;
}

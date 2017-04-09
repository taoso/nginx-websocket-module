#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <ngx_sha1.h>


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
    memset(encoded.data, 0, encoded.len);
    encoded.data[encoded.len] = (u_char)'\0';
    if (encoded.data == NULL) {
        return NULL;
    }

    ngx_encode_base64(&encoded, &decoded);

    return encoded.data;
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

    r->read_event_handler = ngx_http_test_reading;

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_FLUSH);
}

static char *ngx_http_websocket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_websocket_handler;

    return NGX_CONF_OK;
}

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <vips/vips.h>

// Forward declarations for our functions
static ngx_int_t ngx_http_vips_webp_handler(ngx_http_request_t *r);
static char *ngx_http_vips_webp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_vips_webp_init_process(ngx_cycle_t *cycle);
static void ngx_http_vips_webp_exit_process(ngx_cycle_t *cycle);

// Defines the directive that will be used in nginx.conf
static ngx_command_t ngx_http_vips_webp_commands[] = {
    { ngx_string("vips_webp"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_vips_webp,
      0,
      0,
      NULL },

      ngx_null_command
};

// Module context and definition
static ngx_http_module_t ngx_http_vips_webp_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_vips_webp_module = {
    NGX_MODULE_V1,
    &ngx_http_vips_webp_module_ctx, /* module context */
    ngx_http_vips_webp_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_vips_webp_init_process, /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    ngx_http_vips_webp_exit_process, /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

// Initializes libvips when a worker process starts
static ngx_int_t ngx_http_vips_webp_init_process(ngx_cycle_t *cycle) {
    if (VIPS_INIT("nginx-vips-webp")) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "Failed to initialize libvips");
        return NGX_ERROR;
    }
    return NGX_OK;
}

// Cleans up libvips when a worker process exits
static void ngx_http_vips_webp_exit_process(ngx_cycle_t *cycle) {
    vips_shutdown();
}

// Handler function that processes the request
static ngx_int_t ngx_http_vips_webp_handler(ngx_http_request_t *r) {
    // Only process GET and HEAD requests
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    // Construct the full path to the requested JPEG file
    ngx_str_t path;
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    path.len = clcf->root.len + r->uri.len;
    path.data = ngx_palloc(r->pool, path.len);
    if (path.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(path.data, clcf->root.data, clcf->root.len);
    ngx_memcpy(path.data + clcf->root.len, r->uri.data, r->uri.len);

    u_char *c_path = ngx_palloc(r->pool, path.len + 1);
    if (c_path == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(c_path, path.data, path.len);
    c_path[path.len] = '\0';

    // Get file info (stat) to check for existence and get metadata for caching headers.
    ngx_file_info_t fi;
    if (ngx_file_info((const char *)c_path, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "vips_webp: file not found: \"%s\"", c_path);
        return NGX_HTTP_NOT_FOUND;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.last_modified_time = ngx_file_mtime(&fi);
    // Not actually true after conversion, but needed to generate ETag
    r->headers_out.content_length_n = ngx_file_size(&fi);

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_weak_etag(r);

    ngx_int_t rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // Use libvips to load the source JPEG file
    VipsImage *in;
    if (vips_jpegload((const char *)c_path, &in, NULL)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "vips_jpegload failed for file: %s. Vips error: %s",
                      c_path, vips_error_buffer());
        vips_error_clear();
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Convert the image to WEBP format in memory
    void *webp_buffer;
    size_t webp_size;
    if (vips_webpsave_buffer(in, &webp_buffer, &webp_size, NULL)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "vips_webpsave_buffer failed. Vips error: %s",
                      vips_error_buffer());
        vips_error_clear();
        g_object_unref(in);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    g_object_unref(in);

    r->headers_out.status = NGX_HTTP_OK;
    // Update with actual size
    r->headers_out.content_length_n = webp_size;

    ngx_str_set(&r->headers_out.content_type, "image/webp");
    r->headers_out.content_type_len = sizeof("image/webp") - 1;

    // Create a buffer chain to send the response body
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, webp_size);
    if (b == NULL) {
        g_free(webp_buffer);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, webp_buffer, webp_size);
    b->last = b->pos + webp_size;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->memory = 1;

    g_free(webp_buffer);

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_vips_webp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_vips_webp_handler;
    return NGX_CONF_OK;
}

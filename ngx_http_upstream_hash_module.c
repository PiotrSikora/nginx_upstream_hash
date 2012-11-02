/*
 * Hash a variable to choose an upstream server.
 *
 * Copyright (C) Evan Miller
 *
 * This module can be distributed under the same terms as Nginx itself.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if (NGX_HTTP_HEALTHCHECK)
#include <ngx_http_healthcheck_module.h>
#endif

#define ngx_bitvector_index(index) (index / (8 * sizeof(uintptr_t)))
#define ngx_bitvector_bit(index) ((uintptr_t) 1 << (index % (8 * sizeof(uintptr_t))))

typedef struct {
    ngx_http_complex_value_t       *ignore_weights;
} ngx_http_upstream_hash_srv_conf_t;

typedef struct {
    struct sockaddr                *sockaddr;
    socklen_t                       socklen;
    ngx_str_t                       name;
    unsigned                        down:1;
    ngx_int_t                       weight;
#if (NGX_HTTP_HEALTHCHECK)
    ngx_int_t                       health_index;
#endif
} ngx_http_upstream_hash_peer_t;

typedef struct {
    ngx_uint_t                        number;
    ngx_uint_t                        total_weight;
    unsigned                          weighted:1;
    ngx_http_upstream_hash_peer_t     peer[0];
} ngx_http_upstream_hash_peers_t;

typedef struct {
    ngx_http_upstream_hash_peers_t   *peers;
    ngx_uint_t                        hash;
    ngx_str_t                         current_key;
    ngx_str_t                         original_key;
    ngx_uint_t                        try_i;
    uintptr_t                         tried[1];
    unsigned                          ignore_weights:1;
} ngx_http_upstream_hash_peer_data_t;


static ngx_uint_t ngx_http_upstream_get_hash_peer_index(
    ngx_http_upstream_hash_peer_data_t *uhpd);
static void ngx_http_upstream_hash_next_peer(ngx_http_upstream_hash_peer_data_t *uhpd,
        ngx_uint_t *tries, ngx_log_t *log);
static ngx_int_t ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_hash_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);
static void * ngx_http_upstream_hash_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_hash_again(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_init_hash(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
static ngx_uint_t ngx_http_upstream_hash_crc32(u_char *keydata, size_t keylen);
static ngx_int_t ngx_http_upstream_is_down(ngx_http_upstream_hash_peer_t *peer,
    ngx_log_t *log);

static ngx_command_t  ngx_http_upstream_hash_commands[] = {
    { ngx_string("hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_hash,
      0,
      0,
      NULL },

    { ngx_string("hash_again"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_hash_again,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_hash_create_conf,    /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_hash_module_ctx,    /* module context */
    ngx_http_upstream_hash_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t
ngx_http_upstream_get_hash_peer_index(ngx_http_upstream_hash_peer_data_t *uhpd)
{
    ngx_int_t   w;
    ngx_uint_t  i;

    if (uhpd->ignore_weights || !uhpd->peers->weighted) {
        return uhpd->hash % uhpd->peers->number;
    }

    w = uhpd->hash % uhpd->peers->total_weight;

    for (i = 0; i < uhpd->peers->number; i++) {
        w -= uhpd->peers->peer[i].weight;
        if (w < 0) {
            return i;
        }
    }

    /* unreachable */

    return 0;
}


static ngx_int_t
ngx_http_upstream_init_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                       i, j, n, w;
    ngx_http_upstream_server_t      *server;
    ngx_http_upstream_hash_peers_t  *peers;
#if (NGX_HTTP_HEALTHCHECK)
    ngx_int_t                        health_index;
#endif

    us->peer.init = ngx_http_upstream_init_hash_peer;

    if (!us->servers) {

        return NGX_ERROR;
    }

    server = us->servers->elts;

    for (n = 0, w = 0, i = 0; i < us->servers->nelts; i++) {
        n += server[i].naddrs;
        w += server[i].naddrs * server[i].weight;
    }

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_hash_peers_t)
            + sizeof(ngx_http_upstream_hash_peer_t) * n);

    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->number = n;
    peers->weighted = (w != n);
    peers->total_weight = w;

    /* one hostname can have multiple IP addresses in DNS */
    for (n = 0, i = 0; i < us->servers->nelts; i++) {
        for (j = 0; j < server[i].naddrs; j++, n++) {
            peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
            peers->peer[n].socklen = server[i].addrs[j].socklen;
            peers->peer[n].name = server[i].addrs[j].name;
            peers->peer[n].down = server[i].down;
            peers->peer[n].weight = server[i].weight;
#if (NGX_HTTP_HEALTHCHECK)
            if (!server[i].down) {
                health_index =
                    ngx_http_healthcheck_add_peer(us,
                    &server[i].addrs[j], cf->pool);
                if (health_index == NGX_ERROR) {
                    return NGX_ERROR;
                }
                peers->peer[n].health_index = health_index;
            }
#endif
        }
    }

    us->peer.data = peers;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_hash_srv_conf_t   *uhcf;
    ngx_http_upstream_hash_peer_data_t  *uhpd;
    ngx_str_t                            val, s;

    if (ngx_http_script_run(r, &val, us->lengths, 0, us->values) == NULL) {
        return NGX_ERROR;
    }

    uhpd = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_hash_peer_data_t)
            + sizeof(uintptr_t) *
                ((ngx_http_upstream_hash_peers_t *)us->peer.data)->number /
                    (8 * sizeof(uintptr_t)));
    if (uhpd == NULL) {
        return NGX_ERROR;
    }

    uhcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);

    if (uhcf->ignore_weights) {
        if (ngx_http_complex_value(r, uhcf->ignore_weights, &s) != NGX_OK) {
            return NGX_ERROR;
        }

        if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
            uhpd->ignore_weights = 1;
        }
    }

    r->upstream->peer.data = uhpd;

    uhpd->peers = us->peer.data;

    r->upstream->peer.free = ngx_http_upstream_free_hash_peer;
    r->upstream->peer.get = ngx_http_upstream_get_hash_peer;
    r->upstream->peer.tries = us->retries + 1;

    /* must be big enough for the retry keys */
    if ((uhpd->current_key.data = ngx_pcalloc(r->pool, NGX_ATOMIC_T_LEN + val.len)) == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(uhpd->current_key.data, val.data, val.len);
    uhpd->current_key.len = val.len;
    uhpd->original_key = val;
    uhpd->try_i = 0;

    ngx_http_upstream_hash_next_peer(uhpd, &r->upstream->peer.tries, r->connection->log);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream_hash: Starting with %ui", ngx_http_upstream_get_hash_peer_index(uhpd));


    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_hash_peer_data_t  *uhpd = data;
    ngx_http_upstream_hash_peer_t       *peer;
    ngx_uint_t                           peer_index;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "upstream_hash: get upstream request hash peer try %ui", pc->tries);

    pc->cached = 0;
    pc->connection = NULL;

    peer_index = ngx_http_upstream_get_hash_peer_index(uhpd);

    peer = &uhpd->peers->peer[peer_index];


    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "upstream_hash: chose peer %ui w/ hash %ui for tries %ui", peer_index, uhpd->hash, pc->tries);

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    return NGX_OK;
}

/* retry implementation is PECL memcache compatible */
static void
ngx_http_upstream_free_hash_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_hash_peer_data_t  *uhpd = data;
    ngx_uint_t                           current;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
            "upstream_hash: free upstream hash peer try %ui", pc->tries);

    if (state & (NGX_PEER_FAILED|NGX_PEER_NEXT)
            && pc->tries) {
        current = ngx_http_upstream_get_hash_peer_index(uhpd);

        uhpd->tried[ngx_bitvector_index(current)] |= ngx_bitvector_bit(current);
        ngx_http_upstream_hash_next_peer(uhpd, &pc->tries, pc->log);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
          "upstream_hash: Using %ui because %ui failed", ngx_http_upstream_get_hash_peer_index(uhpd), current);
    } else {
        pc->tries = 0;
    }
}

static void ngx_http_upstream_hash_next_peer(ngx_http_upstream_hash_peer_data_t *uhpd,
        ngx_uint_t *tries, ngx_log_t *log) {

    ngx_uint_t current;
    current = ngx_http_upstream_get_hash_peer_index(uhpd);
    do {
       uhpd->current_key.len = ngx_sprintf(uhpd->current_key.data, "%d%V",
           ++uhpd->try_i, &uhpd->original_key) - uhpd->current_key.data;
       uhpd->hash += ngx_http_upstream_hash_crc32(uhpd->current_key.data,
           uhpd->current_key.len);
       current = ngx_http_upstream_get_hash_peer_index(uhpd);
       ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
           "upstream_hash: hashed \"%V\" to %ui", &uhpd->current_key, current);
       //   Loop while there is a try left, we're on one we haven't tried, and
       // the current peer isn't marked down
   } while (--(*tries) && (
       (uhpd->tried[ngx_bitvector_index(current)] & ngx_bitvector_bit(current))
        || ngx_http_upstream_is_down(&uhpd->peers->peer[current], log)));
}

static ngx_int_t ngx_http_upstream_is_down(ngx_http_upstream_hash_peer_t *peer,
    ngx_log_t *log) {
  return peer->down
#if (NGX_HTTP_HEALTHCHECK)
    || ngx_http_healthcheck_is_down(peer->health_index, log)
#endif
    ;
}

/* bit-shift, bit-mask, and non-zero requirement are for libmemcache compatibility */
static ngx_uint_t
ngx_http_upstream_hash_crc32(u_char *keydata, size_t keylen)
{
    ngx_uint_t crc32 = (ngx_crc32_short(keydata, keylen) >> 16) & 0x7fff;
    return crc32 ? crc32 : 1;
}


static void *
ngx_http_upstream_hash_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_hash_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->ignore_weights = NULL;
     */

    return conf;
}


static char *
ngx_http_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_hash_srv_conf_t  *uhcf;
    ngx_http_upstream_srv_conf_t       *uscf;
    ngx_http_script_compile_t           sc;
    ngx_http_compile_complex_value_t    ccv;
    ngx_str_t                          *value, s;
    ngx_array_t                        *vars_lengths, *vars_values;
    ngx_uint_t                          i;

    value = cf->args->elts;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    vars_lengths = NULL;
    vars_values = NULL;

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &vars_lengths;
    sc.values = &vars_values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    uhcf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_hash_module);

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "ignore_weights=", 15) == 0) {

            s.len = value[i].len - 15;
            s.data = &value[i].data[15];

            if (uhcf->ignore_weights != NULL) {
                return "is duplicate";
            }

            uhcf->ignore_weights = ngx_palloc(cf->pool,
                                              sizeof(ngx_http_complex_value_t));
            if (uhcf->ignore_weights == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = uhcf->ignore_weights;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        goto invalid;
    }

    uscf->peer.init_upstream = ngx_http_upstream_init_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_DOWN;

    uscf->values = vars_values->elts;
    uscf->lengths = vars_lengths->elts;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static char *
ngx_http_upstream_hash_again(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_int_t n;

    ngx_str_t *value;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n < 0) {
        return "invalid number";
    }

    uscf->retries = n;

    return NGX_CONF_OK;
}

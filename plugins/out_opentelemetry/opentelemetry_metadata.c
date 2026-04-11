/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_lock.h>
#include <fluent-bit/flb_sds.h>

#include "opentelemetry.h"
#include "opentelemetry_metadata.h"

/* Maximum size of the token JSON response body */
#define FLB_OTEL_METADATA_TOKEN_SIZE_MAX 16384

/*
 * Parse access_token and expires_in from a cloud metadata token JSON response.
 *
 * Unlike flb_oauth2_parse_json_response(), this function does not impose a
 * minimum on expires_in — that is the caller's responsibility.  When the
 * response omits expires_in, *expires_in_out is set to 0; callers should
 * substitute a sensible default (e.g. FLB_OAUTH2_DEFAULT_EXPIRES).
 *
 * Returns 0 on success, -1 when access_token is absent or the JSON is invalid.
 * On success the caller owns *access_token_out and must flb_sds_destroy() it.
 */
static int metadata_parse_token_json(const char *json_data,
                                     size_t json_size,
                                     flb_sds_t *access_token_out,
                                     uint64_t *expires_in_out)
{
    int i;
    int ret;
    int key_len;
    int val_len;
    const char *key;
    const char *val;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;
    char tmp_num[32];
    unsigned long long parsed_val;
    char *end;
    flb_sds_t access_token = NULL;
    uint64_t expires_in = 0;
    int tokens_size = 32;

    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tokens_size);
    if (!tokens) {
        flb_errno();
        return -1;
    }

    ret = jsmn_parse(&parser, json_data, json_size, tokens, tokens_size);
    if (ret <= 0 || tokens[0].type != JSMN_OBJECT) {
        flb_free(tokens);
        return -1;
    }

    for (i = 1; i < ret; i++) {
        t = &tokens[i];

        if (t->type != JSMN_STRING || t->start == -1 || t->end == -1) {
            continue;
        }

        key = json_data + t->start;
        key_len = t->end - t->start;

        if (i + 1 >= ret) {
            break;
        }

        i++;
        t = &tokens[i];
        val = json_data + t->start;
        val_len = t->end - t->start;

        if (key_len == 12 && strncmp(key, "access_token", 12) == 0) {
            if (access_token) {
                flb_sds_destroy(access_token);
            }
            access_token = flb_sds_create_len(val, val_len);
            if (!access_token) {
                flb_free(tokens);
                return -1;
            }
        }
        else if (key_len == 10 && strncmp(key, "expires_in", 10) == 0) {
            if (val_len <= 0 || val_len >= (int) sizeof(tmp_num)) {
                continue;
            }
            strncpy(tmp_num, val, val_len);
            tmp_num[val_len] = '\0';
            if (tmp_num[0] == '-') {
                continue;
            }
            errno = 0;
            parsed_val = strtoull(tmp_num, &end, 10);
            if (errno == 0 && end != tmp_num && *end == '\0') {
                expires_in = (uint64_t) parsed_val;
            }
        }
    }

    flb_free(tokens);

    if (!access_token) {
        return -1;
    }

    *access_token_out = access_token;
    *expires_in_out = expires_in;
    return 0;
}

int flb_otel_metadata_token_create(struct opentelemetry_context *ctx,
                                   struct flb_config *config)
{
    int ret;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;

    /* Parse URL to extract the path for HTTP GET requests */
    ret = flb_utils_url_split(ctx->metadata_token_url,
                              &protocol, &host, &port, &uri);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "metadata: failed to parse URL '%s'",
                      ctx->metadata_token_url);
        return -1;
    }

    /* Only plain HTTP is supported; the metadata endpoint is a link-local
     * address that never requires TLS. */
    if (!protocol || strcasecmp(protocol, "http") != 0) {
        flb_plg_error(ctx->ins,
                      "metadata_token_url only supports http:// URLs");
        flb_free(protocol);
        flb_free(host);
        flb_free(port);
        flb_free(uri);
        return -1;
    }

    ctx->metadata_token_path = flb_sds_create(uri ? uri : "/");

    flb_free(protocol);
    flb_free(host);
    flb_free(port);
    flb_free(uri);

    if (!ctx->metadata_token_path) {
        return -1;
    }

    /* Append optional scope and audience as query parameters to the path.
     * Use '&' if the URL already contains '?', otherwise start with '?'. */
    if (ctx->metadata_token_scope || ctx->metadata_token_audience) {
        const char *sep = strchr(ctx->metadata_token_path, '?') ? "&" : "?";

        if (ctx->metadata_token_scope) {
            ctx->metadata_token_path = flb_sds_cat(ctx->metadata_token_path,
                                                   sep, 1);
            ctx->metadata_token_path = flb_sds_cat(ctx->metadata_token_path,
                                                   "scopes=", 7);
            ctx->metadata_token_path = flb_sds_cat(ctx->metadata_token_path,
                                                   ctx->metadata_token_scope,
                                                   strlen(ctx->metadata_token_scope));
            sep = "&";
        }

        if (ctx->metadata_token_audience) {
            ctx->metadata_token_path = flb_sds_cat(ctx->metadata_token_path,
                                                   sep, 1);
            ctx->metadata_token_path = flb_sds_cat(ctx->metadata_token_path,
                                                   "audience=", 9);
            ctx->metadata_token_path = flb_sds_cat(ctx->metadata_token_path,
                                                   ctx->metadata_token_audience,
                                                   strlen(ctx->metadata_token_audience));
        }

        if (!ctx->metadata_token_path) {
            return -1;
        }
    }

    /* Create a synchronous (non-async) upstream for the metadata endpoint */
    ctx->metadata_u = flb_upstream_create_url(config, ctx->metadata_token_url,
                                              FLB_IO_TCP, NULL);
    if (!ctx->metadata_u) {
        flb_plg_error(ctx->ins, "metadata: failed to create upstream");
        flb_sds_destroy(ctx->metadata_token_path);
        ctx->metadata_token_path = NULL;
        return -1;
    }

    flb_stream_disable_async_mode(&ctx->metadata_u->base);

    ret = pthread_mutex_init(&ctx->metadata_mutex, NULL);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "metadata: failed to init mutex");
        flb_upstream_destroy(ctx->metadata_u);
        ctx->metadata_u = NULL;
        flb_sds_destroy(ctx->metadata_token_path);
        ctx->metadata_token_path = NULL;
        return -1;
    }
    ctx->metadata_mutex_initialized = FLB_TRUE;

    return 0;
}

int flb_otel_metadata_token_refresh(struct opentelemetry_context *ctx)
{
    int ret;
    size_t b_sent;
    struct flb_connection *conn;
    struct flb_http_client *c;
    const char *sep;
    time_t now;
    time_t effective_ttl;
    flb_sds_t payload;
    flb_sds_t new_token = NULL;
    flb_sds_t new_token_type = NULL;
    uint64_t raw_expires_in;

    if (!ctx->metadata_token_url) {
        return 0;
    }

    pthread_mutex_lock(&ctx->metadata_mutex);

    /*
     * Check expiry under both locks: metadata_mutex prevents concurrent
     * refreshes; oauth2_ctx->lock synchronizes with the write in
     * flb_oauth2_invalidate_token() which uses only oauth2_ctx->lock.
     */
    ret = flb_lock_acquire(&ctx->oauth2_ctx->lock,
                           FLB_LOCK_DEFAULT_RETRY_LIMIT,
                           FLB_LOCK_DEFAULT_RETRY_DELAY);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "metadata: failed to acquire oauth2 lock");
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }
    now = time(NULL);
    if (ctx->oauth2_ctx->expires_at > 0 &&
        now < ctx->oauth2_ctx->expires_at - FLB_OAUTH2_DEFAULT_SKEW_SECS) {
        flb_lock_release(&ctx->oauth2_ctx->lock,
                         FLB_LOCK_DEFAULT_RETRY_LIMIT,
                         FLB_LOCK_DEFAULT_RETRY_DELAY);
        flb_plg_debug(ctx->ins, "metadata: token still valid, skipping refresh");
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return 0;
    }
    flb_lock_release(&ctx->oauth2_ctx->lock,
                     FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);

    conn = flb_upstream_conn_get(ctx->metadata_u);
    if (!conn) {
        flb_plg_error(ctx->ins, "metadata: failed to connect to endpoint");
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    c = flb_http_client(conn, FLB_HTTP_GET, ctx->metadata_token_path,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(conn);
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    flb_http_buffer_size(c, FLB_OTEL_METADATA_TOKEN_SIZE_MAX);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Add optional custom header (e.g. "Metadata-Flavor: Google") */
    if (ctx->metadata_token_header) {
        sep = strstr(ctx->metadata_token_header, ": ");
        if (sep) {
            size_t name_len = (size_t)(sep - ctx->metadata_token_header);
            size_t val_len  = strlen(sep + 2);
            flb_http_add_header(c,
                                ctx->metadata_token_header, name_len,
                                sep + 2, val_len);
        }
        else {
            flb_plg_warn(ctx->ins,
                         "metadata: metadata_token_header '%s' is not in "
                         "'Name: Value' format; header will not be sent",
                         ctx->metadata_token_header);
        }
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0 || c->resp.status != 200) {
        if (ret != 0) {
            flb_plg_warn(ctx->ins,
                         "metadata: HTTP GET failed (ret=%d)", ret);
        }
        else {
            flb_plg_warn(ctx->ins,
                         "metadata: HTTP GET returned status=%d",
                         c->resp.status);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(conn);
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    payload = flb_sds_create_len(c->resp.payload, c->resp.payload_size);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(conn);

    if (!payload) {
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    /*
     * Parse access_token and expires_in from the JSON response.
     * metadata_parse_token_json() sets raw_expires_in to 0 when the
     * server omits the field; we fall back to FLB_OAUTH2_DEFAULT_EXPIRES.
     */
    ret = metadata_parse_token_json(payload, flb_sds_len(payload),
                                    &new_token, &raw_expires_in);
    flb_sds_destroy(payload);

    if (ret != 0) {
        flb_plg_error(ctx->ins, "metadata: failed to parse token JSON response");
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    if (raw_expires_in == 0) {
        effective_ttl = (time_t) FLB_OAUTH2_DEFAULT_EXPIRES;
    }
    else {
        effective_ttl = (time_t) raw_expires_in;
    }

    /* Cap the effective TTL to metadata_token_refresh if configured */
    if (ctx->metadata_token_refresh > 0 &&
        ctx->metadata_token_refresh < (int) effective_ttl) {
        effective_ttl = (time_t) ctx->metadata_token_refresh;
    }

    /*
     * If the server returned an expires_in that is <= the oauth2 skew
     * constant, flb_oauth2_get_access_token() would treat the freshly-
     * fetched token as already expired and trigger the oauth2 POST
     * refresh path (which has no credentials and fails).  Clamp to
     * ensure the token stays valid past the skew window.
     */
    if (effective_ttl <= FLB_OAUTH2_DEFAULT_SKEW_SECS) {
        flb_plg_warn(ctx->ins,
                     "metadata: server expires_in %llu is <= skew (%d); "
                     "clamping to %d",
                     (unsigned long long) raw_expires_in,
                     FLB_OAUTH2_DEFAULT_SKEW_SECS,
                     FLB_OAUTH2_DEFAULT_SKEW_SECS + 1);
        effective_ttl = FLB_OAUTH2_DEFAULT_SKEW_SECS + 1;
    }

    new_token_type = flb_sds_create("Bearer");
    if (!new_token_type) {
        flb_sds_destroy(new_token);
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    /* Update the oauth2 context under its lock */
    ret = flb_lock_acquire(&ctx->oauth2_ctx->lock,
                           FLB_LOCK_DEFAULT_RETRY_LIMIT,
                           FLB_LOCK_DEFAULT_RETRY_DELAY);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "metadata: failed to acquire oauth2 lock");
        flb_sds_destroy(new_token);
        flb_sds_destroy(new_token_type);
        pthread_mutex_unlock(&ctx->metadata_mutex);
        return -1;
    }

    if (ctx->oauth2_ctx->access_token) {
        flb_sds_destroy(ctx->oauth2_ctx->access_token);
    }
    if (ctx->oauth2_ctx->token_type) {
        flb_sds_destroy(ctx->oauth2_ctx->token_type);
    }
    ctx->oauth2_ctx->access_token = new_token;
    ctx->oauth2_ctx->token_type   = new_token_type;
    ctx->oauth2_ctx->expires_in   = (uint64_t) effective_ttl;
    ctx->oauth2_ctx->expires_at   = time(NULL) + effective_ttl;

    flb_lock_release(&ctx->oauth2_ctx->lock,
                     FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);

    flb_plg_debug(ctx->ins,
                  "metadata: token refreshed, expires in %ld seconds",
                  (long) effective_ttl);
    pthread_mutex_unlock(&ctx->metadata_mutex);

    return 0;
}

void flb_otel_metadata_token_destroy(struct opentelemetry_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->metadata_mutex_initialized) {
        pthread_mutex_destroy(&ctx->metadata_mutex);
        ctx->metadata_mutex_initialized = FLB_FALSE;
    }

    if (ctx->metadata_u) {
        flb_upstream_destroy(ctx->metadata_u);
        ctx->metadata_u = NULL;
    }

    if (ctx->metadata_token_path) {
        flb_sds_destroy(ctx->metadata_token_path);
        ctx->metadata_token_path = NULL;
    }
}

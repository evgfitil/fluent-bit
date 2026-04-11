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

#include <fluent-bit.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_oauth2.h>
#include <monkey/mk_core.h>
#include <monkey/mk_lib.h>
#include <monkey/mk_http.h>
#include <unistd.h>
#include "flb_tests_runtime.h"
#include "../../plugins/out_opentelemetry/opentelemetry.h"

/* Test function declarations */
void flb_test_otel_default_config(void);
void flb_test_metadata_token_url_sets_context(void);
void flb_test_metadata_token_default_refresh(void);
void flb_test_metadata_token_custom_refresh(void);
void flb_test_metadata_token_mutual_exclusion(void);
void flb_test_metadata_token_https_rejected(void);
void flb_test_metadata_token_low_refresh_rejected(void);
void flb_test_no_metadata_token_backward_compat(void);
void flb_test_metadata_token_fetch_on_first_flush(void);
void flb_test_metadata_token_refresh_on_expiry(void);
void flb_test_metadata_token_custom_header(void);
void flb_test_metadata_token_fetch_failure(void);
void flb_test_metadata_token_legacy_post(void);
void flb_test_metadata_token_401_recovery(void);
void flb_test_metadata_token_refresh_interval_override(void);
void flb_test_metadata_token_missing_expires_in(void);
void flb_test_metadata_token_short_expires_in(void);
void flb_test_metadata_token_scope_query_param(void);
void flb_test_metadata_token_audience_query_param(void);
void flb_test_metadata_token_both_query_params(void);
void flb_test_metadata_token_scope_without_url_ignored(void);

/* Test list */
TEST_LIST = {
    {"default_config",                    flb_test_otel_default_config},
    {"metadata_token_url_sets_context",   flb_test_metadata_token_url_sets_context},
    {"metadata_token_default_refresh",    flb_test_metadata_token_default_refresh},
    {"metadata_token_custom_refresh",     flb_test_metadata_token_custom_refresh},
    {"metadata_token_mutual_exclusion",   flb_test_metadata_token_mutual_exclusion},
    {"metadata_token_https_rejected",     flb_test_metadata_token_https_rejected},
    {"metadata_token_low_refresh_rejected",
        flb_test_metadata_token_low_refresh_rejected},
    {"no_metadata_token_backward_compat", flb_test_no_metadata_token_backward_compat},
    {"metadata_token_fetch_on_first_flush", flb_test_metadata_token_fetch_on_first_flush},
    {"metadata_token_refresh_on_expiry",    flb_test_metadata_token_refresh_on_expiry},
    {"metadata_token_custom_header",        flb_test_metadata_token_custom_header},
    {"metadata_token_fetch_failure",        flb_test_metadata_token_fetch_failure},
    {"metadata_token_legacy_post",              flb_test_metadata_token_legacy_post},
    {"metadata_token_401_recovery",             flb_test_metadata_token_401_recovery},
    {"metadata_token_refresh_interval_override",
        flb_test_metadata_token_refresh_interval_override},
    {"metadata_token_missing_expires_in",
        flb_test_metadata_token_missing_expires_in},
    {"metadata_token_short_expires_in",
        flb_test_metadata_token_short_expires_in},
    {"metadata_token_scope_query_param",
        flb_test_metadata_token_scope_query_param},
    {"metadata_token_audience_query_param",
        flb_test_metadata_token_audience_query_param},
    {"metadata_token_both_query_params",
        flb_test_metadata_token_both_query_params},
    {"metadata_token_scope_without_url_ignored",
        flb_test_metadata_token_scope_without_url_ignored},
    {NULL, NULL}
};

/* Helper: return the opentelemetry plugin context from a running output instance. */
static struct opentelemetry_context *get_otel_ctx(flb_ctx_t *ctx, int out_ffd)
{
    struct flb_output_instance *ins;

    ins = flb_output_get_instance(ctx->config, out_ffd);
    if (!ins) {
        return NULL;
    }
    return (struct opentelemetry_context *) ins->context;
}

/*
 * Smoke test: initialize the OTel output plugin with a minimal configuration
 * and verify that the plugin starts without errors. No real server is needed
 * because the upstream connection is established lazily at flush time.
 */
void flb_test_otel_default_config(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "10",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",   "test",
                   "host",    "127.0.0.1",
                   "port",    "14317",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: setting metadata_token_url creates the oauth2 context and enables oauth2.
 */
void flb_test_metadata_token_url_sets_context(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "10",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "14317",
                   "metadata_token_url", "http://169.254.169.254/metadata/token",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    TEST_CHECK(otel_ctx->oauth2_config.enabled == FLB_TRUE);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: omitting metadata_token_refresh defaults to 3600 seconds.
 */
void flb_test_metadata_token_default_refresh(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "10",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "14317",
                   "metadata_token_url", "http://169.254.169.254/metadata/token",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    TEST_CHECK(otel_ctx->metadata_token_refresh == 3600);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: metadata_token_refresh is stored correctly when explicitly set.
 */
void flb_test_metadata_token_custom_refresh(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "10",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                  "test",
                   "host",                   "127.0.0.1",
                   "port",                   "14317",
                   "metadata_token_url",     "http://169.254.169.254/metadata/token",
                   "metadata_token_refresh", "1800",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    TEST_CHECK(otel_ctx->metadata_token_refresh == 1800);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: configuring both metadata_token_url and standard OAuth2 is rejected.
 */
void flb_test_metadata_token_mutual_exclusion(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "10",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                "test",
                   "host",                 "127.0.0.1",
                   "port",                 "14317",
                   "metadata_token_url",   "http://169.254.169.254/metadata/token",
                   "oauth2.enable",        "true",
                   "oauth2.token_url",     "http://localhost:19999/token",
                   "oauth2.client_id",     "test-client",
                   "oauth2.client_secret", "test-secret",
                   NULL);

    /* init must fail: metadata_token_url and standard OAuth2 cannot be combined */
    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_destroy(ctx);
}

/*
 * Test: metadata_token_url with an https:// scheme is rejected at init time.
 * The metadata endpoint is a link-local address; TLS is not supported.
 */
void flb_test_metadata_token_https_rejected(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "10",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "14317",
                   "metadata_token_url", "https://169.254.169.254/metadata/token",
                   NULL);

    /* init must fail: https:// is not a supported scheme */
    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_destroy(ctx);
}

/*
 * Test: metadata_token_refresh <= FLB_OAUTH2_DEFAULT_SKEW_SECS (60) is rejected.
 * Values at or below the skew threshold cause the freshly-fetched token to be
 * treated as already expired by flb_oauth2_get_access_token(), triggering the
 * oauth2 POST refresh path which has no credentials and returns FLB_RETRY on
 * every flush.
 */
void flb_test_metadata_token_low_refresh_rejected(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "10",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                  "test",
                   "host",                   "127.0.0.1",
                   "port",                   "14317",
                   "metadata_token_url",     "http://169.254.169.254/metadata/token",
                   "metadata_token_refresh", "60",
                   NULL);

    /* init must fail: refresh=60 equals FLB_OAUTH2_DEFAULT_SKEW_SECS */
    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_destroy(ctx);
}

/*
 * Test: plugin starts normally without any metadata options (backward compatibility).
 */
void flb_test_no_metadata_token_backward_compat(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "10",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "host",  "127.0.0.1",
                   "port",  "14317",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    TEST_CHECK(otel_ctx->metadata_token_url == NULL);
    TEST_CHECK(otel_ctx->oauth2_ctx == NULL);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* ============================================================
 * Task 4: mock server infrastructure and token fetch tests
 * ============================================================ */

/* Port for the mock metadata HTTP server used in Task 4 tests. */
#define MOCK_METADATA_PORT 18901

/*
 * JSON responses returned by the mock metadata endpoint.
 * The short-expiry variant is used to force a token refresh in tests.
 */
#define MOCK_TOKEN_RESPONSE \
    "{\"access_token\":\"test-token-123\"," \
    "\"token_type\":\"Bearer\"," \
    "\"expires_in\":3600}"

#define MOCK_TOKEN_SHORT_EXPIRY \
    "{\"access_token\":\"test-token-123\"," \
    "\"token_type\":\"Bearer\"," \
    "\"expires_in\":1}"

/* Shared state updated by the mock server callback. */
static pthread_mutex_t g_meta_lock     = PTHREAD_MUTEX_INITIALIZER;
static int             g_meta_calls    = 0;     /* times the endpoint was hit */
static int             g_short_expiry  = 0;     /* if set, return expires_in:1 */

static void meta_state_reset(void)
{
    pthread_mutex_lock(&g_meta_lock);
    g_meta_calls   = 0;
    g_short_expiry = 0;
    pthread_mutex_unlock(&g_meta_lock);
}

/* Monkey server callback for the mock metadata endpoint. */
static void cb_mock_metadata(mk_request_t *request, void *data)
{
    const char *resp;
    (void) data;
    (void) request;

    pthread_mutex_lock(&g_meta_lock);
    g_meta_calls++;
    resp = g_short_expiry ? MOCK_TOKEN_SHORT_EXPIRY : MOCK_TOKEN_RESPONSE;
    pthread_mutex_unlock(&g_meta_lock);

    mk_http_status(request, 200);
    mk_http_header(request, "Content-Type", 12, "application/json", 16);
    mk_http_send(request, (char *) resp, strlen(resp), NULL);
    mk_http_done(request);
}

/* Start a Monkey HTTP server at 127.0.0.1:port serving the mock metadata JSON. */
static mk_ctx_t *mock_meta_start(int port)
{
    char addr[32];
    mk_ctx_t *mk;
    int vid;

    mk = mk_create();
    if (!mk) {
        return NULL;
    }

    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    mk_config_set(mk, "Listen", addr, NULL);

    vid = mk_vhost_create(mk, NULL);
    mk_vhost_set(mk, vid, "Name", "mock-metadata", NULL);
    mk_vhost_handler(mk, vid, "/", cb_mock_metadata, NULL);

    mk_start(mk);
    return mk;
}

/* Stop and destroy a Monkey server started by mock_meta_start(). */
static void mock_meta_stop(mk_ctx_t *mk)
{
    if (mk) {
        mk_stop(mk);
        mk_destroy(mk);
    }
}

/*
 * Variant mock server for flb_test_metadata_token_custom_header.
 * This callback verifies that the client sent the expected custom header
 * ("Metadata-Flavor: Google") in the metadata GET request.
 */
#define MOCK_METADATA_PORT_CH 18904

static pthread_mutex_t g_ch_lock        = PTHREAD_MUTEX_INITIALIZER;
static int             g_ch_header_seen = 0;

static void ch_state_reset(void)
{
    pthread_mutex_lock(&g_ch_lock);
    g_ch_header_seen = 0;
    pthread_mutex_unlock(&g_ch_lock);
}

static void cb_mock_metadata_ch(mk_request_t *request, void *data)
{
    struct mk_http_header *hdr;
    (void) data;

    /* "Metadata-Flavor" is a custom (non-standard) header; use MK_HEADER_OTHER
     * to search the extra-headers array populated by the parser.
     * The parser lowercases all custom header keys, so search with lowercase. */
    hdr = mk_http_header_get(MK_HEADER_OTHER, request, "metadata-flavor", 15);
    if (hdr != NULL && hdr->val.data != NULL &&
        hdr->val.len >= 6 &&
        strncmp(hdr->val.data, "Google", 6) == 0) {
        pthread_mutex_lock(&g_ch_lock);
        g_ch_header_seen = 1;
        pthread_mutex_unlock(&g_ch_lock);
    }

    mk_http_status(request, 200);
    mk_http_header(request, "Content-Type", 12, "application/json", 16);
    mk_http_send(request, (char *) MOCK_TOKEN_RESPONSE,
                 strlen(MOCK_TOKEN_RESPONSE), NULL);
    mk_http_done(request);
}

static mk_ctx_t *mock_meta_start_ch(int port)
{
    char addr[32];
    mk_ctx_t *mk;
    int vid;

    mk = mk_create();
    if (!mk) {
        return NULL;
    }

    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    mk_config_set(mk, "Listen", addr, NULL);

    vid = mk_vhost_create(mk, NULL);
    mk_vhost_set(mk, vid, "Name", "mock-metadata-ch", NULL);
    mk_vhost_handler(mk, vid, "/", cb_mock_metadata_ch, NULL);

    mk_start(mk);
    return mk;
}

/*
 * Test: on the first flush the metadata endpoint is called and the access_token
 * is populated in oauth2_ctx.  The OTel send destination (port 19998) is
 * intentionally unreachable so the flush fails after the metadata fetch; this
 * does not affect the token state that the test inspects.
 */
void flb_test_metadata_token_fetch_on_first_flush(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;
    char metadata_url[128];
    mk_ctx_t *mk;
    int calls;

    meta_state_reset();

    mk = mock_meta_start(MOCK_METADATA_PORT);
    TEST_CHECK(mk != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "19998",
                   "metadata_token_url", metadata_url,
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Inject a record to trigger a flush cycle. */
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);

    /* Metadata endpoint must have been called at least once. */
    pthread_mutex_lock(&g_meta_lock);
    calls = g_meta_calls;
    pthread_mutex_unlock(&g_meta_lock);
    TEST_CHECK(calls >= 1);

    /* Token must have been populated from the mock response. */
    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    if (otel_ctx->oauth2_ctx) {
        TEST_CHECK(otel_ctx->oauth2_ctx->access_token != NULL);
        if (otel_ctx->oauth2_ctx->access_token) {
            TEST_CHECK(strcmp(otel_ctx->oauth2_ctx->access_token,
                              "test-token-123") == 0);
        }
    }

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk);
}

/*
 * Test: when the token is expired before the second flush, the metadata
 * endpoint is called again and the token is refreshed.
 *
 * The mock returns expires_in:1 so the token expires after 1 second.
 * The test waits 2 seconds between the first and second flush to guarantee
 * expiry has occurred.
 */
void flb_test_metadata_token_refresh_on_expiry(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char metadata_url[128];
    mk_ctx_t *mk;
    int calls_after_first;
    int calls_after_second;

    meta_state_reset();

    pthread_mutex_lock(&g_meta_lock);
    g_short_expiry = 1;
    pthread_mutex_unlock(&g_meta_lock);

    mk = mock_meta_start(MOCK_METADATA_PORT);
    TEST_CHECK(mk != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "19998",
                   "metadata_token_url", metadata_url,
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* First flush: fetch the short-lived token. */
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"first\"}]", 21);
    sleep(2);

    pthread_mutex_lock(&g_meta_lock);
    calls_after_first = g_meta_calls;
    pthread_mutex_unlock(&g_meta_lock);
    TEST_CHECK(calls_after_first >= 1);

    /* Wait for the 1-second token to expire, then trigger another flush. */
    sleep(2);
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"second\"}]", 22);
    sleep(2);

    pthread_mutex_lock(&g_meta_lock);
    calls_after_second = g_meta_calls;
    pthread_mutex_unlock(&g_meta_lock);

    /* The metadata endpoint must have been called a second time. */
    TEST_CHECK(calls_after_second > calls_after_first);

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk);
}

/*
 * Test: when metadata_token_header is configured the custom header is actually
 * transmitted to the metadata endpoint (not just stored in the context).
 * The header-checking mock (cb_mock_metadata_ch) sets g_ch_header_seen when
 * it receives "Metadata-Flavor: Google", so a successful token fetch with
 * g_ch_header_seen == 1 proves the header reached the wire.
 */
void flb_test_metadata_token_custom_header(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;
    char metadata_url[128];
    mk_ctx_t *mk;
    int header_seen;

    ch_state_reset();

    mk = mock_meta_start_ch(MOCK_METADATA_PORT_CH);
    TEST_CHECK(mk != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT_CH);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                  "test",
                   "host",                   "127.0.0.1",
                   "port",                   "19998",
                   "metadata_token_url",     metadata_url,
                   "metadata_token_header",  "Metadata-Flavor: Google",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);

    /* The configured header must be stored in the plugin context. */
    TEST_CHECK(otel_ctx->metadata_token_header != NULL);
    if (otel_ctx->metadata_token_header) {
        TEST_CHECK(strcmp(otel_ctx->metadata_token_header,
                          "Metadata-Flavor: Google") == 0);
    }

    /* Trigger a flush; the metadata endpoint must be reached. */
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    /* Verify the mock server was actually called. */
    pthread_mutex_lock(&g_ch_lock);
    header_seen = g_ch_header_seen;
    pthread_mutex_unlock(&g_ch_lock);

    /* Token must be populated. */
    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    if (otel_ctx->oauth2_ctx) {
        TEST_CHECK(otel_ctx->oauth2_ctx->access_token != NULL);
    }

    /* The mock must have received the Metadata-Flavor: Google header. */
    TEST_CHECK(header_seen == 1);

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk);
}

/*
 * Test: when metadata_token_url points to an unreachable server the flush does
 * not crash the process and the token remains NULL.
 */
void flb_test_metadata_token_fetch_failure(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    /* Both the metadata URL and the OTel endpoint are unreachable. */
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "19998",
                   "metadata_token_url", "http://127.0.0.1:19997/metadata/token",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push a record; the fetch will fail but the plugin must not crash. */
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    /* Token remains NULL because the fetch failed. */
    TEST_CHECK(otel_ctx->oauth2_ctx->access_token == NULL);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* ============================================================
 * Task 7: legacy HTTP/1.1 path and edge case tests
 * ============================================================ */

/* Separate port for Task 7 mock server to avoid conflicts with Task 4 tests. */
#define MOCK_METADATA_PORT_T7 18902

/* Response type selectors for the Task 7 mock. */
#define MOCK_T7_RESP_NORMAL    0   /* expires_in: 3600 */
#define MOCK_T7_RESP_60S       1   /* expires_in: 60 */
#define MOCK_T7_RESP_NO_EXPIRY 2   /* no expires_in field */
#define MOCK_T7_RESP_120S      3   /* expires_in: 120 */

#define MOCK_TOKEN_60S_EXPIRY \
    "{\"access_token\":\"test-token-123\"," \
    "\"token_type\":\"Bearer\"," \
    "\"expires_in\":60}"

#define MOCK_TOKEN_120S_EXPIRY \
    "{\"access_token\":\"test-token-123\"," \
    "\"token_type\":\"Bearer\"," \
    "\"expires_in\":120}"

#define MOCK_TOKEN_NO_EXPIRY \
    "{\"access_token\":\"test-token-123\"," \
    "\"token_type\":\"Bearer\"}"

static pthread_mutex_t g_t7_lock      = PTHREAD_MUTEX_INITIALIZER;
static int             g_t7_calls     = 0;
static int             g_t7_resp_type = MOCK_T7_RESP_NORMAL;

static void t7_state_reset(void)
{
    pthread_mutex_lock(&g_t7_lock);
    g_t7_calls     = 0;
    g_t7_resp_type = MOCK_T7_RESP_NORMAL;
    pthread_mutex_unlock(&g_t7_lock);
}

static void cb_mock_metadata_t7(mk_request_t *request, void *data)
{
    const char *resp;
    (void) data;
    (void) request;

    pthread_mutex_lock(&g_t7_lock);
    g_t7_calls++;
    switch (g_t7_resp_type) {
    case MOCK_T7_RESP_60S:
        resp = MOCK_TOKEN_60S_EXPIRY;
        break;
    case MOCK_T7_RESP_NO_EXPIRY:
        resp = MOCK_TOKEN_NO_EXPIRY;
        break;
    case MOCK_T7_RESP_120S:
        resp = MOCK_TOKEN_120S_EXPIRY;
        break;
    default:
        resp = MOCK_TOKEN_RESPONSE;
        break;
    }
    pthread_mutex_unlock(&g_t7_lock);

    mk_http_status(request, 200);
    mk_http_header(request, "Content-Type", 12, "application/json", 16);
    mk_http_send(request, (char *) resp, strlen(resp), NULL);
    mk_http_done(request);
}

static mk_ctx_t *mock_meta_start_t7(int port)
{
    char addr[32];
    mk_ctx_t *mk;
    int vid;

    mk = mk_create();
    if (!mk) {
        return NULL;
    }

    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    mk_config_set(mk, "Listen", addr, NULL);

    vid = mk_vhost_create(mk, NULL);
    mk_vhost_set(mk, vid, "Name", "mock-metadata-t7", NULL);
    mk_vhost_handler(mk, vid, "/", cb_mock_metadata_t7, NULL);

    mk_start(mk);
    return mk;
}

/*
 * Mock OTel HTTP/1.1 destination server used by flb_test_metadata_token_legacy_post
 * and flb_test_metadata_token_401_recovery.
 *
 * The callback records the Authorization header value from each POST request
 * and can be configured to serve a configurable number of 401 responses before
 * switching to 200, allowing tests to exercise the 401 recovery code path in
 * opentelemetry.c.
 */
#define MOCK_OTEL_PORT 18903

static pthread_mutex_t g_otel_lock          = PTHREAD_MUTEX_INITIALIZER;
static int             g_otel_calls         = 0;
static int             g_otel_401_remaining = 0;
static char            g_otel_auth_header[256];

static void otel_state_reset(void)
{
    pthread_mutex_lock(&g_otel_lock);
    g_otel_calls         = 0;
    g_otel_401_remaining = 0;
    memset(g_otel_auth_header, 0, sizeof(g_otel_auth_header));
    pthread_mutex_unlock(&g_otel_lock);
}

static void cb_mock_otel(mk_request_t *request, void *data)
{
    struct mk_http_header *auth;
    char auth_val[256];
    int serve_401;
    (void) data;

    /* Read the Authorization header before acquiring the global lock. */
    auth_val[0] = '\0';
    auth = mk_http_header_get(MK_HEADER_AUTHORIZATION, request, NULL, 0);
    if (auth != NULL && auth->val.data != NULL && auth->val.len > 0) {
        snprintf(auth_val, sizeof(auth_val),
                 "%.*s", (int) auth->val.len, auth->val.data);
    }

    pthread_mutex_lock(&g_otel_lock);
    g_otel_calls++;
    serve_401 = (g_otel_401_remaining > 0);
    if (serve_401) {
        g_otel_401_remaining--;
    }
    if (auth_val[0] != '\0') {
        strncpy(g_otel_auth_header, auth_val, sizeof(g_otel_auth_header) - 1);
        g_otel_auth_header[sizeof(g_otel_auth_header) - 1] = '\0';
    }
    pthread_mutex_unlock(&g_otel_lock);

    if (serve_401) {
        mk_http_status(request, 401);
        mk_http_done(request);
        return;
    }

    mk_http_status(request, 200);
    mk_http_done(request);
}

static mk_ctx_t *mock_otel_start(int port)
{
    char addr[32];
    mk_ctx_t *mk;
    int vid;

    mk = mk_create();
    if (!mk) {
        return NULL;
    }

    snprintf(addr, sizeof(addr), "127.0.0.1:%d", port);
    mk_config_set(mk, "Listen", addr, NULL);

    vid = mk_vhost_create(mk, NULL);
    mk_vhost_set(mk, vid, "Name", "mock-otel", NULL);
    mk_vhost_handler(mk, vid, "/", cb_mock_otel, NULL);

    mk_start(mk);
    return mk;
}

static void mock_otel_stop(mk_ctx_t *mk)
{
    if (mk) {
        mk_stop(mk);
        mk_destroy(mk);
    }
}

/*
 * Test: metadata token is fetched correctly when the OTel plugin runs in
 * legacy HTTP/1.1 mode (http2=off) AND the Bearer token is actually sent in
 * the Authorization header of the outgoing POST request.
 *
 * A mock OTel server (cb_mock_otel) records the Authorization header so the
 * test can verify the token reached the wire, not just the oauth2_ctx struct.
 */
void flb_test_metadata_token_legacy_post(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;
    char metadata_url[128];
    char otel_port_str[16];
    mk_ctx_t *mk_meta;
    mk_ctx_t *mk_otel;
    int calls;
    char auth_header[256];

    t7_state_reset();
    otel_state_reset();

    mk_meta = mock_meta_start_t7(MOCK_METADATA_PORT_T7);
    TEST_CHECK(mk_meta != NULL);

    mk_otel = mock_otel_start(MOCK_OTEL_PORT);
    TEST_CHECK(mk_otel != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT_T7);
    snprintf(otel_port_str, sizeof(otel_port_str), "%d", MOCK_OTEL_PORT);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               otel_port_str,
                   "http2",              "off",
                   "metadata_token_url", metadata_url,
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);

    /* Confirm legacy (HTTP/1.1) path is active. */
    TEST_CHECK(otel_ctx->enable_http2_flag == FLB_FALSE);

    /* Metadata endpoint must have been called at least once. */
    pthread_mutex_lock(&g_t7_lock);
    calls = g_t7_calls;
    pthread_mutex_unlock(&g_t7_lock);
    TEST_CHECK(calls >= 1);

    /* Token must be populated in legacy mode the same as in HTTP/2 mode. */
    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    if (otel_ctx->oauth2_ctx) {
        TEST_CHECK(otel_ctx->oauth2_ctx->access_token != NULL);
        if (otel_ctx->oauth2_ctx->access_token) {
            TEST_CHECK(strcmp(otel_ctx->oauth2_ctx->access_token,
                              "test-token-123") == 0);
        }
    }

    /* The mock OTel server must have received the Bearer token in the
     * Authorization header, proving the legacy POST actually carries the token
     * (not just that the token was stored in oauth2_ctx). */
    pthread_mutex_lock(&g_otel_lock);
    strncpy(auth_header, g_otel_auth_header, sizeof(auth_header) - 1);
    auth_header[sizeof(auth_header) - 1] = '\0';
    pthread_mutex_unlock(&g_otel_lock);
    TEST_CHECK(strcmp(auth_header, "Bearer test-token-123") == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk_meta);
    mock_otel_stop(mk_otel);
}

/*
 * Test: a real 401 response from the OTel destination causes the plugin to
 * invalidate the token and re-fetch it from the metadata endpoint.
 *
 * The mock OTel server (cb_mock_otel) is configured to return 401 on the first
 * request, then 200.  This exercises the HTTP/1.1 401 retry path in
 * opentelemetry_legacy_post() which calls flb_oauth2_invalidate_token()
 * (sets expires_at = 0) and returns FLB_RETRY.  The next flush re-fetches the
 * token via flb_otel_metadata_token_refresh() and retries the OTel request.
 *
 * Note: the HTTP/2 401 branch in opentelemetry_post() (opentelemetry.c line
 * 624) requires a gRPC-capable mock server and is verified manually.
 */
void flb_test_metadata_token_401_recovery(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char metadata_url[128];
    char otel_port_str[16];
    mk_ctx_t *mk_meta;
    mk_ctx_t *mk_otel;
    int calls_after_first;
    int calls_after_second;
    int otel_calls;

    t7_state_reset();
    otel_state_reset();

    /* Configure mock OTel to serve one 401 before switching to 200. */
    pthread_mutex_lock(&g_otel_lock);
    g_otel_401_remaining = 1;
    pthread_mutex_unlock(&g_otel_lock);

    mk_meta = mock_meta_start_t7(MOCK_METADATA_PORT_T7);
    TEST_CHECK(mk_meta != NULL);

    mk_otel = mock_otel_start(MOCK_OTEL_PORT);
    TEST_CHECK(mk_otel != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT_T7);
    snprintf(otel_port_str, sizeof(otel_port_str), "%d", MOCK_OTEL_PORT);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               otel_port_str,
                   "http2",              "off",
                   "metadata_token_url", metadata_url,
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /*
     * First flush: token is fetched from metadata (g_t7_calls becomes 1),
     * POST is sent to OTel mock which returns 401.
     * opentelemetry_legacy_post() calls flb_oauth2_invalidate_token()
     * (sets expires_at = 0) and returns FLB_RETRY directly.
     * No second metadata fetch happens yet.
     */
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"first\"}]", 21);
    sleep(2);

    pthread_mutex_lock(&g_t7_lock);
    calls_after_first = g_t7_calls;
    pthread_mutex_unlock(&g_t7_lock);
    /* At least the initial metadata fetch occurred. */
    TEST_CHECK(calls_after_first >= 1);

    /*
     * Second flush: flb_otel_metadata_token_refresh() sees expires_at = 0
     * (set by flb_oauth2_invalidate_token()), fetches a new token from the
     * metadata endpoint, then sends the POST to OTel which returns 200.
     */
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"second\"}]", 22);
    sleep(2);

    pthread_mutex_lock(&g_t7_lock);
    calls_after_second = g_t7_calls;
    pthread_mutex_unlock(&g_t7_lock);

    /* The second flush must have triggered a new metadata fetch. */
    TEST_CHECK(calls_after_second > calls_after_first);

    /* OTel mock must have been called at least twice: 401 + success. */
    pthread_mutex_lock(&g_otel_lock);
    otel_calls = g_otel_calls;
    pthread_mutex_unlock(&g_otel_lock);
    TEST_CHECK(otel_calls >= 2);

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk_meta);
    mock_otel_stop(mk_otel);
}

/*
 * Test: when the mock returns expires_in:120 and metadata_token_refresh is 90,
 * the effective token TTL is capped at 90 seconds (not 120).
 * metadata_token_refresh must be > FLB_OAUTH2_DEFAULT_SKEW_SECS (60).
 */
void flb_test_metadata_token_refresh_interval_override(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;
    char metadata_url[128];
    mk_ctx_t *mk;
    time_t before_fetch;
    time_t expires_at;

    t7_state_reset();

    pthread_mutex_lock(&g_t7_lock);
    g_t7_resp_type = MOCK_T7_RESP_120S;
    pthread_mutex_unlock(&g_t7_lock);

    mk = mock_meta_start_t7(MOCK_METADATA_PORT_T7);
    TEST_CHECK(mk != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT_T7);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                  "test",
                   "host",                   "127.0.0.1",
                   "port",                   "19998",
                   "metadata_token_url",     metadata_url,
                   "metadata_token_refresh", "90",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    before_fetch = time(NULL);
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);

    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    if (otel_ctx && otel_ctx->oauth2_ctx) {
        expires_at = otel_ctx->oauth2_ctx->expires_at;
        /* TTL must be ~90s, not 120s (metadata_token_refresh caps expires_in). */
        TEST_CHECK(expires_at <= before_fetch + 92);
        TEST_CHECK(expires_at >= before_fetch + 88);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk);
}

/*
 * Test: when the metadata response omits expires_in, the oauth2 layer defaults
 * to FLB_OAUTH2_DEFAULT_EXPIRES (300 seconds) for the token TTL.
 */
void flb_test_metadata_token_missing_expires_in(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;
    char metadata_url[128];
    mk_ctx_t *mk;
    time_t before_fetch;
    time_t expires_at;

    t7_state_reset();

    pthread_mutex_lock(&g_t7_lock);
    g_t7_resp_type = MOCK_T7_RESP_NO_EXPIRY;
    pthread_mutex_unlock(&g_t7_lock);

    mk = mock_meta_start_t7(MOCK_METADATA_PORT_T7);
    TEST_CHECK(mk != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT_T7);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "19998",
                   "metadata_token_url", metadata_url,
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    before_fetch = time(NULL);
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);

    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    if (otel_ctx && otel_ctx->oauth2_ctx) {
        TEST_CHECK(otel_ctx->oauth2_ctx->access_token != NULL);
        expires_at = otel_ctx->oauth2_ctx->expires_at;
        /*
         * No expires_in in the mock response: flb_oauth2_parse_json_response()
         * falls back to FLB_OAUTH2_DEFAULT_EXPIRES.  metadata_token_refresh
         * defaults to 3600 which is larger, so the default wins.
         */
        TEST_CHECK(expires_at >= before_fetch + FLB_OAUTH2_DEFAULT_EXPIRES - 10);
        TEST_CHECK(expires_at <= before_fetch + FLB_OAUTH2_DEFAULT_EXPIRES + 10);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk);
}

/*
 * Test: when the metadata response returns expires_in <= FLB_OAUTH2_DEFAULT_SKEW_SECS
 * (60 seconds), the effective token TTL is clamped to SKEW+1 so that
 * flb_oauth2_get_access_token() does not treat the freshly-fetched token as
 * already expired and trigger the POST refresh path which has no credentials.
 */
void flb_test_metadata_token_short_expires_in(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;
    char metadata_url[128];
    mk_ctx_t *mk;
    time_t before_fetch;
    time_t expires_at;

    t7_state_reset();

    pthread_mutex_lock(&g_t7_lock);
    g_t7_resp_type = MOCK_T7_RESP_60S;
    pthread_mutex_unlock(&g_t7_lock);

    mk = mock_meta_start_t7(MOCK_METADATA_PORT_T7);
    TEST_CHECK(mk != NULL);

    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d/metadata/token", MOCK_METADATA_PORT_T7);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "0.5",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",              "test",
                   "host",               "127.0.0.1",
                   "port",               "19998",
                   "metadata_token_url", metadata_url,
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    before_fetch = time(NULL);
    flb_lib_push(ctx, in_ffd, "[0, {\"msg\": \"hello\"}]", 21);
    sleep(2);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);

    TEST_CHECK(otel_ctx->oauth2_ctx != NULL);
    if (otel_ctx && otel_ctx->oauth2_ctx) {
        TEST_CHECK(otel_ctx->oauth2_ctx->access_token != NULL);
        expires_at = otel_ctx->oauth2_ctx->expires_at;
        /*
         * Server returned expires_in:60 which equals FLB_OAUTH2_DEFAULT_SKEW_SECS.
         * The refresh path must clamp it to SKEW+1 so the token is not
         * immediately considered expired by flb_oauth2_get_access_token().
         */
        TEST_CHECK(expires_at >= before_fetch + FLB_OAUTH2_DEFAULT_SKEW_SECS + 1);
        TEST_CHECK(expires_at <= before_fetch + FLB_OAUTH2_DEFAULT_SKEW_SECS + 3);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
    mock_meta_stop(mk);
}

/*
 * Test: metadata_token_scope appends ?scopes=<value> to the metadata GET path.
 */
void flb_test_metadata_token_scope_query_param(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "10",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                "test",
                   "host",                 "127.0.0.1",
                   "port",                 "14317",
                   "metadata_token_url",   "http://169.254.169.254/metadata/token",
                   "metadata_token_scope", "https://www.googleapis.com/auth/cloud-platform",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    if (otel_ctx) {
        TEST_CHECK(otel_ctx->metadata_token_path != NULL);
        if (otel_ctx->metadata_token_path) {
            TEST_CHECK(strstr(otel_ctx->metadata_token_path,
                              "?scopes=https://www.googleapis.com/auth/cloud-platform")
                       != NULL);
        }
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: metadata_token_audience appends ?audience=<value> to the metadata GET path.
 */
void flb_test_metadata_token_audience_query_param(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "10",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                   "test",
                   "host",                    "127.0.0.1",
                   "port",                    "14317",
                   "metadata_token_url",      "http://169.254.169.254/metadata/token",
                   "metadata_token_audience", "my-service-account@project.iam.gserviceaccount.com",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    if (otel_ctx) {
        TEST_CHECK(otel_ctx->metadata_token_path != NULL);
        if (otel_ctx->metadata_token_path) {
            TEST_CHECK(strstr(otel_ctx->metadata_token_path,
                              "?audience=my-service-account@project.iam.gserviceaccount.com")
                       != NULL);
        }
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: setting both metadata_token_scope and metadata_token_audience appends
 * ?scopes=<scope>&audience=<audience> to the metadata GET path.
 */
void flb_test_metadata_token_both_query_params(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "10",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                   "test",
                   "host",                    "127.0.0.1",
                   "port",                    "14317",
                   "metadata_token_url",      "http://169.254.169.254/metadata/token",
                   "metadata_token_scope",    "cloud-platform",
                   "metadata_token_audience", "my-audience",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    if (otel_ctx) {
        TEST_CHECK(otel_ctx->metadata_token_path != NULL);
        if (otel_ctx->metadata_token_path) {
            TEST_CHECK(strstr(otel_ctx->metadata_token_path,
                              "?scopes=cloud-platform&audience=my-audience")
                       != NULL);
        }
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: setting metadata_token_scope without metadata_token_url does not crash;
 * the plugin starts normally without any metadata token context.
 */
void flb_test_metadata_token_scope_without_url_ignored(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct opentelemetry_context *otel_ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "10",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                "test",
                   "host",                 "127.0.0.1",
                   "port",                 "14317",
                   "metadata_token_scope", "https://www.googleapis.com/auth/cloud-platform",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    otel_ctx = get_otel_ctx(ctx, out_ffd);
    TEST_CHECK(otel_ctx != NULL);
    if (otel_ctx) {
        /* No metadata_token_url: no oauth2 context and no path should be set */
        TEST_CHECK(otel_ctx->oauth2_ctx == NULL);
        TEST_CHECK(otel_ctx->metadata_token_path == NULL);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

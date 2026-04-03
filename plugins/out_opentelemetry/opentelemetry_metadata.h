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

#ifndef FLB_OUT_OPENTELEMETRY_METADATA_H
#define FLB_OUT_OPENTELEMETRY_METADATA_H

#include <fluent-bit/flb_config.h>

/* Forward declaration to avoid circular includes */
struct opentelemetry_context;

/*
 * flb_otel_metadata_token_create - initialize upstream and mutex for metadata
 * token fetch.  Must be called once during plugin init when metadata_token_url
 * is configured.
 */
int flb_otel_metadata_token_create(struct opentelemetry_context *ctx,
                                   struct flb_config *config);

/*
 * flb_otel_metadata_token_refresh - fetch a new token from the metadata
 * endpoint if the current token has expired or is about to expire.  Safe to
 * call on every flush; returns immediately when the cached token is fresh.
 * Returns 0 on success, -1 on error.
 */
int flb_otel_metadata_token_refresh(struct opentelemetry_context *ctx);

/*
 * flb_otel_metadata_token_destroy - release upstream, mutex, and cached path
 * created by flb_otel_metadata_token_create().
 */
void flb_otel_metadata_token_destroy(struct opentelemetry_context *ctx);

#endif /* FLB_OUT_OPENTELEMETRY_METADATA_H */

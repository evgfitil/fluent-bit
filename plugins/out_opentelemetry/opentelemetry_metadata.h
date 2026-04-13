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

struct opentelemetry_context;

int flb_otel_metadata_token_create(struct opentelemetry_context *ctx,
                                   struct flb_config *config);
int flb_otel_metadata_token_refresh(struct opentelemetry_context *ctx);
void flb_otel_metadata_token_destroy(struct opentelemetry_context *ctx);

#endif /* FLB_OUT_OPENTELEMETRY_METADATA_H */

/*
 *  Copyright (c) 2025 Metaform Systems, Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems, Inc. - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.verification.fixtures;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.function.Consumer;

/**
 * Testing functions.
 */
public class TestFixtures {

    /**
     * Executes the request and applies the given verification.
     */
    public static void executeRequest(Request request, Consumer<Response> verification) {
        var client = new OkHttpClient();
        var call = client.newCall(request);
        try (var response = call.execute()) {
            verification.accept(response);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

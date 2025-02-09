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

package org.eclipse.dataspacetck.dcp.system.did;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import static java.net.URLDecoder.decode;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Resolves DID documents. Only Web DIDs are supported.
 */
public class DidClient {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DID_SCHEME = "did";
    private static final String DID_WEB_PREFIX = "web:";
    private static final String DID_DOCUMENT = "did.json";
    private static final String WELL_KNOWN = "/.well-known";

    private final String scheme;

    public DidClient(boolean https) {
        scheme = https ? "https" : "http";
    }

    /**
     * Resolves the DID document for the given DID.
     */
    public DidDocument resolveDocument(String did) {
        var request = new Request.Builder().url(didToUrl(did)).build();
        var client = new OkHttpClient();
        var call = client.newCall(request);
        try (var response = call.execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException("Unexpected response: " + response.code());
            }
            //noinspection DataFlowIssue
            return MAPPER.readValue(response.body().string(), DidDocument.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public String didToUrl(String did) {
        var identifier = parseDid(did);
        var url = identifier.toString();
        if (identifier.getPath().isEmpty()) {
            url += WELL_KNOWN;
        }
        return decode(url + "/" + DID_DOCUMENT, UTF_8);
    }

    private URL parseDid(String did) {
        var uri = URI.create(did);
        if (!DID_SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("Unsupported DID scheme: " + uri.getScheme());
        }

        var part = uri.getRawSchemeSpecificPart();
        if (!part.startsWith(DID_WEB_PREFIX)) {
            throw new IllegalArgumentException("Invalid DID format, the URN must specify the 'web' DID Method: " + did);
        } else if (part.endsWith(":")) {
            throw new IllegalArgumentException("Invalid DID format, the URN must not end with ':': " + did);
        }

        var host = part.substring(DID_WEB_PREFIX.length()).replace(':', '/');
        try {
            return new URL(scheme + "://" + host);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}

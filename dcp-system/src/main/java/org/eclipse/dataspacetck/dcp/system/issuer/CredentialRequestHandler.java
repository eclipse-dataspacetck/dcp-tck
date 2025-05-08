/*
 *  Copyright (c) 2025 Metaform Systems Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems Inc. - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.system.issuer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.dataspacetck.core.api.system.HandlerResponse;
import org.eclipse.dataspacetck.core.api.system.ProtocolHandler;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

public class CredentialRequestHandler implements ProtocolHandler {
    private final IssuerService issuerService;
    private final ObjectMapper objectMapper;

    public CredentialRequestHandler(IssuerService issuerService, ObjectMapper objectMapper) {
        this.issuerService = issuerService;
        this.objectMapper = objectMapper;
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public HandlerResponse apply(String path, Map<String, List<String>> headers, InputStream body) {
        var authHeaders = headers.get("Authorization");
        if (authHeaders == null || authHeaders.isEmpty() || authHeaders.get(0).isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
            return new HandlerResponse(401, "Missing access token");
        }

        var id = path.substring(path.lastIndexOf("/") + 1);
        var idToken = headers.get("Authorization").get(0);
        idToken = idToken.replace("Bearer", "").trim();


        var result = issuerService.getCredentialStatus(idToken, id);

        if (result.succeeded()) {
            try {
                var json = objectMapper.writeValueAsString(result.getContent());
                return new HandlerResponse(200, json);
            } catch (JsonProcessingException e) {
                return new HandlerResponse(400, "Failed to serialize CredentialStatus");
            }
        }
        return switch (result.getErrorType()) {
            case BAD_REQUEST -> new HandlerResponse(400, result.getFailure());
            case UNAUTHORIZED -> new HandlerResponse(401, result.getFailure());
            case NOT_FOUND -> new HandlerResponse(404, result.getFailure());
            case GENERAL_ERROR, NO_ERROR -> new HandlerResponse(500, result.getFailure());
        };
    }
}

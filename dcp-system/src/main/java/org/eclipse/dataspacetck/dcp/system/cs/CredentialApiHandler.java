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

package org.eclipse.dataspacetck.dcp.system.cs;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.dataspacetck.core.api.system.HandlerResponse;
import org.eclipse.dataspacetck.core.api.system.ProtocolHandler;
import org.eclipse.dataspacetck.dcp.system.issuer.IssuerService;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;

/**
 * This handler handles requests to the "/credentials" endpoint. As per DCP Spec, this endpoint is used both for
 * CredentialsMessages and CredentialRequestMessages.
 * Therefor, upon receiving a message, this handler delegates based on the message type.
 */
public record CredentialApiHandler(CredentialService credentialService, ObjectMapper mapper,
                                   IssuerService issuerService) implements ProtocolHandler {
    private static final TypeReference<Map<String, Object>> MAP_REF = new TypeReference<>() {
    };

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {
        var authHeaders = headers.get("Authorization");
        if (authHeaders == null || authHeaders.isEmpty() || authHeaders.get(0).isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
            return new HandlerResponse(401, "Missing access token");
        }

        var idToken = headers.get("Authorization").get(0);
        idToken = idToken.replace("Bearer", "").trim();

        try {
            var msg = mapper.readValue(body, MAP_REF);
            var msgType = msg.getOrDefault(TYPE, "").toString();

            return switch (msgType) {
                case CREDENTIAL_MESSAGE_TYPE -> toResponse(credentialService.writeCredentials(idToken, msg));
                case CREDENTIAL_REQUEST_MESSAGE_TYPE ->
                        toResponse(issuerService.processCredentialRequest(idToken, msg));
                default ->
                        new HandlerResponse(400, "Invalid message type, expected either '%s' or '%s', got '%s'".formatted(CREDENTIAL_MESSAGE_TYPE, CREDENTIAL_REQUEST_MESSAGE_TYPE, msgType));
            };

        } catch (IOException e) {
            return new HandlerResponse(400, "Invalid JSON");
        }

    }

    @NotNull
    private HandlerResponse toResponse(Result<?> result) {
        var content = result.getContent();
        Map<String, String> headers = emptyMap();
        if (content != null) {
            headers = Map.of("Location", content.toString());
        }

        return switch (result.getErrorType()) {
            case BAD_REQUEST -> new HandlerResponse(400, result.getFailure());
            case UNAUTHORIZED -> new HandlerResponse(401, result.getFailure());
            case NOT_FOUND -> new HandlerResponse(404, result.getFailure());
            case GENERAL_ERROR -> new HandlerResponse(500, result.getFailure());
            case NO_ERROR -> new HandlerResponse(201, "", headers);
        };
    }
}

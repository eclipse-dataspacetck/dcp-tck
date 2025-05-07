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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.dataspacetck.core.api.system.HandlerResponse;
import org.eclipse.dataspacetck.core.api.system.ProtocolHandler;
import org.eclipse.dataspacetck.dcp.system.issuer.IssuerService;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;

public class CredentialApiHandler implements ProtocolHandler {
    private final CredentialService credentialService;
    private final ObjectMapper mapper;
    private final IssuerService issuerService;

    public CredentialApiHandler(CredentialService credentialService, ObjectMapper mapper, IssuerService issuerService) {
        this.credentialService = credentialService;
        this.mapper = mapper;
        this.issuerService = issuerService;
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {
        var authHeaders = headers.get("Authorization");
        if (authHeaders == null || authHeaders.isEmpty() || authHeaders.get(0).isEmpty() || !authHeaders.get(0).startsWith("Bearer ")) {
            return new HandlerResponse(401, "Missing access token");
        }

        var idToken = headers.get("Authorization").get(0);
        idToken = idToken.replace("Bearer", "").trim();

        try {
            // todo: add a registry of handlers mapped to the message type
            //noinspection unchecked
            var msg = (Map<String, Object>) mapper.readValue(body, Map.class);
            var msgType = msg.get(TYPE);
            if (msgType.equals(CREDENTIAL_MESSAGE_TYPE)) {
                return handleCredentialMessage(idToken, msg);
            } else if (msgType.equals(CREDENTIAL_REQUEST_MESSAGE_TYPE)) {
                return handleCredentialRequestMessage(idToken, msg);
            }
            return new HandlerResponse(400, "Invalid message type, expected either '%s' or '%s', got '%s".formatted(CREDENTIAL_MESSAGE_TYPE, CREDENTIAL_REQUEST_MESSAGE_TYPE, msgType));
        } catch (IOException | ParseException e) {
            return new HandlerResponse(400, "Invalid JSON");
        }

    }

    @NotNull
    private HandlerResponse handleCredentialRequestMessage(String idToken, Map<String, Object> msg) throws JsonProcessingException, ParseException {

        var credentialsMsg = issuerService.processCredentialRequest(idToken, msg);
        if (credentialsMsg.succeeded()) {
            Executors.newSingleThreadScheduledExecutor().schedule(() -> {
                ((CredentialServiceImpl) credentialService).storeCredentials(credentialsMsg.getContent());
            }, 1, SECONDS);
        }

        var failure = credentialsMsg.getFailure();
        return switch (credentialsMsg.getErrorType()) {
            case BAD_REQUEST -> new HandlerResponse(400, failure);
            case UNAUTHORIZED -> new HandlerResponse(401, failure);
            case NOT_FOUND -> new HandlerResponse(404, failure);
            case GENERAL_ERROR -> new HandlerResponse(500, failure);
            case NO_ERROR -> new HandlerResponse(201, "");
        };
    }

    private HandlerResponse handleCredentialMessage(String idToken, Map<String, Object> msg) {
        Result<Void> result;
        result = credentialService.writeCredentials(idToken, msg);

        if (result.succeeded()) {
            return new HandlerResponse(200, "");
        }
        var failure = result.getFailure();
        return switch (result.getErrorType()) {
            case BAD_REQUEST -> new HandlerResponse(400, failure);
            case UNAUTHORIZED -> new HandlerResponse(401, failure);
            case NOT_FOUND -> new HandlerResponse(404, failure);
            default -> new HandlerResponse(500, failure);
        };
    }
}

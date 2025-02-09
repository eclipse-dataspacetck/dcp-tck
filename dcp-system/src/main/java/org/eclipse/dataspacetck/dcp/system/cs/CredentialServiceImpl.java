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

package org.eclipse.dataspacetck.dcp.system.cs;

import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_RESPONSE_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.message.MessageFunctions.baseMessage;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * Implementation used for test verification.
 */
public class CredentialServiceImpl implements CredentialService {
    private String baseEndpoint;
    private String did;
    private KeyService keyService;
    private TokenValidationService tokenService;

    private Map<String, Map<String, Object>> credentials = new ConcurrentHashMap<>();

    public CredentialServiceImpl(String baseEndpoint,
                                 TokenValidationService tokenService,
                                 String did,
                                 KeyService keyService) {
        this.baseEndpoint = baseEndpoint;
        this.tokenService = tokenService;
        this.did = did;
        this.keyService = keyService;
    }

    @Override
    public Result<Map<String, Object>> presentationQueryMessage(String token, Map<String, Object> message) {
        var jwtResult = tokenService.validateToken(token);
        if (jwtResult.failed()) {
            return jwtResult.convert();
        }

        if (message.containsKey(PRESENTATION) && message.containsKey(SCOPE)) {
            return failure("Request contains both presentation and scope attributes");
        }

        return message.containsKey(PRESENTATION) ? processPresentationQuery(message) : processScopeQuery(message);
    }

    @Override
    public Result<Void> writeCredentials(String token, List<Map<String, Object>> message) {
        return Result.success();
    }

    private Result<Map<String, Object>> processScopeQuery(Map<String, Object> message) {
        return processBaseMessage(message);
    }

    private Result<Map<String, Object>> processPresentationQuery(Map<String, Object> message) {
        return processBaseMessage(message);
    }

    private Result<Map<String, Object>> processBaseMessage(Map<String, Object> message) {
        var response = baseMessage(PRESENTATION_RESPONSE_MESSAGE);
        response.put(PRESENTATION, List.of());
        return success(response);
    }

}

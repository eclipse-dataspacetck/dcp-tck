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

import org.eclipse.dataspacetck.dcp.system.generation.PresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.stream.Collectors.toMap;
import static org.eclipse.dataspacetck.dcp.system.generation.PresentationGenerator.PresentationFormat.JWT;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_DEFINITION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_RESPONSE_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE_ALIAS;
import static org.eclipse.dataspacetck.dcp.system.service.Result.ErrorType.BAD_REQUEST;
import static org.eclipse.dataspacetck.dcp.system.service.Result.ErrorType.NOT_FOUND;
import static org.eclipse.dataspacetck.dcp.system.service.Result.ErrorType.UNAUTHORIZED;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * Implementation used for test verification.
 */
public class CredentialServiceImpl implements CredentialService {
    private String holderDid;

    private final SecureTokenServer secureTokenServer;

    private Map<PresentationGenerator.PresentationFormat, PresentationGenerator> generators;
    private Map<String, List<VcContainer>> credentialsByType = new ConcurrentHashMap<>();

    public CredentialServiceImpl(String holderDid, List<PresentationGenerator> generators, SecureTokenServer secureTokenServer) {
        this.generators = generators.stream().collect(toMap(PresentationGenerator::getFormat, v -> v));
        this.holderDid = holderDid;
        this.secureTokenServer = secureTokenServer;
    }

    @Override
    public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
        var validationResult = secureTokenServer.validateReadToken(bearerDid, accessToken);
        if (validationResult.failed()) {
            return failure(validationResult.getFailure(), UNAUTHORIZED);
        }
        if (message.containsKey(PRESENTATION_DEFINITION) && message.containsKey(SCOPE)) {
            return failure("Request cannot contain both a scope and presentation definition", BAD_REQUEST);
        }
        var scopes = validationResult.getContent();
        return message.containsKey(PRESENTATION_DEFINITION) ? processPresentationQuery(message, scopes, bearerDid)
                : processScopeQuery(message, scopes, bearerDid);
    }

    @Override
    public Result<Void> writeCredentials(String bearerDid, String correlationId, List<VcContainer> containers) {
        var validationResult = secureTokenServer.validateWrite(bearerDid, correlationId);
        if (validationResult.failed()) {
            return failure(validationResult.getFailure(), UNAUTHORIZED);
        }
        containers.forEach(container -> container.credential().getType()
                .forEach(type -> credentialsByType.computeIfAbsent(type, k -> new ArrayList<>()).add(container)));
        return Result.success();
    }

    private Result<Map<String, Object>> processScopeQuery(Map<String, Object> message, List<String> scopes, String audience) {
        @SuppressWarnings("unchecked")
        var requestedScopes = (List<String>) message.get(SCOPE);
        var scopeTypes = new ArrayList<String>();
        for (var requestedScope : requestedScopes) {
            if (!requestedScope.startsWith(SCOPE_TYPE_ALIAS)) {
                return Result.failure("Invalid scope type: " + requestedScope);
            }
            scopeTypes.add(requestedScope.substring(SCOPE_TYPE_ALIAS.length()));
        }
        List<VcContainer> credentials = scopeTypes.stream()
                .flatMap(c -> credentialsByType.get(c).stream())
                .filter(Objects::nonNull)
                .toList();
        if (credentials.isEmpty()) {
            return failure("No credentials found", NOT_FOUND);
        }
        for (var container : credentials) {
            boolean found = false;
            for (var type : container.credential().getType()) {
                if (scopes.contains(type)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return failure("Access denied", UNAUTHORIZED);
            }
        }
        return processBaseMessage(credentials, audience);
    }

    private Result<Map<String, Object>> processPresentationQuery(Map<String, Object> message, List<String> scopes, String audience) {
        return processBaseMessage(List.of(), audience);
    }

    private Result<Map<String, Object>> processBaseMessage(List<VcContainer> credentials, String audience) {
        var presentation = generators.get(JWT).generatePresentation(audience, holderDid, credentials);
        var response = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_RESPONSE_MESSAGE)
                .property(PRESENTATION, List.of(presentation.getContent()))
                .build();
        return success(response);
    }


}

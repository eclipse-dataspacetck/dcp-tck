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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.dcp.system.generation.PresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toMap;
import static org.eclipse.dataspacetck.dcp.system.generation.PresentationGenerator.PresentationFormat.JWT;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_DEFINITION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_RESPONSE_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VC;
import static org.eclipse.dataspacetck.dcp.system.service.Result.ErrorType.BAD_REQUEST;
import static org.eclipse.dataspacetck.dcp.system.service.Result.ErrorType.UNAUTHORIZED;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * Implementation used for test verification.
 */
public class CredentialServiceImpl implements CredentialService {
    public static final Pattern SCOPE_PATTERN = Pattern.compile("(org.eclipse.dspace.dcp.vc.type):(?<type>.*):(.*)");
    private final SecureTokenServer secureTokenServer;
    private final String holderDid;
    private final Map<PresentationGenerator.PresentationFormat, PresentationGenerator> generators;
    private final Map<String, List<VcContainer>> credentialsByType = new ConcurrentHashMap<>();
    private final TokenValidationService tokenService;
    private final ObjectMapper mapper;
    private CredentialService delegate;

    public CredentialServiceImpl(String holderDid,
                                 List<PresentationGenerator> generators,
                                 SecureTokenServer secureTokenServer,
                                 TokenValidationService tokenService,
                                 ObjectMapper mapper) {
        this.generators = generators.stream().collect(toMap(PresentationGenerator::getFormat, v -> v));
        this.holderDid = holderDid;
        this.secureTokenServer = secureTokenServer;
        this.tokenService = tokenService;
        this.mapper = mapper;
    }

    @Override
    public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
        if (delegate != null) {
            return delegate.presentationQueryMessage(bearerDid, accessToken, message);
        }
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
    public Result<Void> writeCredentials(String idTokenJwt, Map<String, Object> credentialMessage) {
        if (delegate != null) {
            return delegate.writeCredentials(idTokenJwt, credentialMessage);
        }
        var validationResult = secureTokenServer.validateWrite(idTokenJwt, tokenService);
        if (validationResult.failed()) {
            return failure(validationResult.getFailure(), UNAUTHORIZED);
        }

        return storeCredentials(credentialMessage);
    }

    @Override
    public Result<Void> offerCredentials(String idTokenJwt, InputStream body) {
        if (delegate != null) {
            return delegate.offerCredentials(idTokenJwt, body);
        }
        var validationResult = secureTokenServer.validateWrite(idTokenJwt, tokenService);
        if (validationResult.failed()) {
            return failure(validationResult.getFailure(), UNAUTHORIZED);
        }

        try {
            var message = mapper.readValue(body, CredentialOfferMessage.class);
            if (!message.validate()) {
                return failure("Invalid message", BAD_REQUEST);
            }

            return success();
        } catch (IOException e) {
            return failure("Invalid JSON: " + e.getMessage(), BAD_REQUEST);
        }
    }

    @Override
    public Collection<VcContainer> getCredentials() {
        if (delegate != null) {
            return delegate.getCredentials();
        }
        return credentialsByType.values().stream().flatMap(Collection::stream).toList();
    }

    @Override
    public void withDelegate(CredentialService delegate) {
        this.delegate = delegate;
    }

    @NotNull
    private Result<Void> storeCredentials(Map<String, Object> credentialMessage) {
        var message = mapper.convertValue(credentialMessage, CredentialMessage.class);
        if (!message.validate()) {
            return failure("Invalid message", BAD_REQUEST);
        }
        message.getCredentials()
                .forEach(cred -> {
                    var container = new VcContainer(cred.payload(), createCredential(cred), CredentialFormat.valueOf(cred.format()));
                    credentialsByType.computeIfAbsent(cred.credentialType(), k -> new ArrayList<>()).add(container);
                });
        return success();
    }

    private VerifiableCredential createCredential(CredentialMessage.CredentialContainer cred) {

        try {
            var claims = (Map<String, Object>) SignedJWT.parse(cred.payload()).getJWTClaimsSet().getClaim(VC);
            return mapper.convertValue(claims, VerifiableCredential.class);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private Result<Map<String, Object>> processScopeQuery(Map<String, Object> message, List<String> scopes, String audience) {
        @SuppressWarnings("unchecked")
        var requestedScopes = (List<String>) message.get(SCOPE);
        var scopeTypes = new ArrayList<String>();
        for (var requestedScope : requestedScopes) {
            var matcher = SCOPE_PATTERN.matcher(requestedScope);
            if (!matcher.matches()) {
                return failure("Invalid scope type: " + requestedScope);
            }
            var type = matcher.group("type");
            scopeTypes.add(type);
        }
        var credentials = scopeTypes.stream()
                .flatMap(c -> ofNullable(credentialsByType.get(c)).stream().flatMap(Collection::stream))
                .filter(Objects::nonNull)
                .toList();
        // technically, responding with an empty credentials array is nonsensical, but allowed
        // if (credentials.isEmpty()) {
        //    return failure("No credentials found", NOT_FOUND);
        // }
        for (var container : credentials) {
            boolean found = false;
            for (var type : container.credential().getType()) {
                if (scopes.stream().anyMatch(scope -> scope.startsWith(type))) {
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

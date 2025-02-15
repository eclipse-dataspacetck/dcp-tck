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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.ValidationMessage;
import org.eclipse.dataspacetck.core.api.system.HandlerResponse;
import org.eclipse.dataspacetck.core.spi.boot.Monitor;
import org.eclipse.dataspacetck.dcp.system.handler.AbstractProtocolHandler;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static java.util.stream.Collectors.joining;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;
import static org.eclipse.dataspacetck.dcp.system.util.Parsers.parseBearerToken;
import static org.eclipse.dataspacetck.dcp.system.util.Validators.validateBearerTokenHeader;

/**
 * Handler for resolution the API.
 */
public class PresentationHandler extends AbstractProtocolHandler {
    private final CredentialService credentialService;
    private final TokenValidationService tokenService;
    private final ObjectMapper mapper;
    private final Monitor monitor;

    public PresentationHandler(CredentialService credentialService,
                               TokenValidationService tokenService,
                               ObjectMapper mapper,
                               Monitor monitor) {
        super("/presentation/presentation-query-message-schema.json");
        this.credentialService = credentialService;
        this.tokenService = tokenService;
        this.mapper = mapper;
        this.monitor = monitor;
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {
        try {
            var message = mapper.readValue(body, Map.class);
            if (!PRESENTATION_QUERY_MESSAGE.equals(message.get(TYPE))) {
                monitor.enableError().message(format("Message is not a %s", PRESENTATION_QUERY_MESSAGE));
                return new HandlerResponse(400, null);
            }
            var tokenHeaders = headers.get(AUTHORIZATION);
            if (tokenHeaders == null || tokenHeaders.isEmpty()) {
                return new HandlerResponse(401, null);
            }

            var unparsedToken = tokenHeaders.get(0);
            if (!validateBearerTokenHeader(unparsedToken)) {
                return new HandlerResponse(401, null);
            }

            var idToken = parseBearerToken(unparsedToken);
            var jwtResult = tokenService.validateToken(idToken);
            if (jwtResult.failed()) {
                return new HandlerResponse(401, null);
            }

            var jwt = jwtResult.getContent();
            var accessToken = jwt.getJWTClaimsSet().getClaimAsString(TOKEN);

            var schemaResult = schema.validate(mapper.convertValue(message, JsonNode.class));
            if (!schemaResult.isEmpty()) {
                var error = format("Schema validation failed: %s", schemaResult.stream().map(ValidationMessage::getMessage).collect(joining("\n")));
                monitor.enableError().message(error).resetMode();
               return new HandlerResponse(400, error);
            }

            var issuer = jwt.getJWTClaimsSet().getIssuer();
            //noinspection unchecked
            var result = credentialService.presentationQueryMessage(issuer, accessToken, message);
            if (result.succeeded()) {
                return new HandlerResponse(200, mapper.writeValueAsString(result.getContent()));
            } else {
                int code;
                switch (result.getErrorType()) {
                    case NOT_FOUND -> {
                        code = 404;
                    }
                    case UNAUTHORIZED -> {
                        code = 401;
                    }
                    case BAD_REQUEST -> {
                        code = 400;
                    }
                    default -> {
                        monitor.enableError().message(format("%s failed: %s", PRESENTATION_QUERY_MESSAGE, result.getFailure())).resetMode();
                        code = 500;
                    }
                }
                return new HandlerResponse(code, null);
            }
        } catch (IOException e) {
            throw new AssertionError(format("Error handling %s", PRESENTATION_QUERY_MESSAGE), e);
        } catch (ParseException e) {
            throw new AssertionError("Invalid access token", e);
        }
    }

}

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
import org.eclipse.dataspacetck.core.api.system.HandlerResponse;
import org.eclipse.dataspacetck.core.api.system.ProtocolHandler;
import org.eclipse.dataspacetck.core.spi.boot.Monitor;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;
import static org.eclipse.dataspacetck.dcp.system.util.Parsers.parseBearerToken;
import static org.eclipse.dataspacetck.dcp.system.util.Validators.validateBearerTokenHeader;

/**
 * Handler for resolution the API.
 */
public class PresentationHandler implements ProtocolHandler {
    private final CredentialService credentialService;
    private final ObjectMapper mapper;
    private final Monitor monitor;

    public PresentationHandler(CredentialService credentialService, ObjectMapper mapper, Monitor monitor) {
        this.credentialService = credentialService;
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
                monitor.enableError().message("Missing auth token");
                return new HandlerResponse(401, null);
            }

            var unparsedToken = tokenHeaders.get(0);
            if (!validateBearerTokenHeader(unparsedToken)) {
                monitor.enableError().message("Invalid auth token");
                return new HandlerResponse(401, null);
            }

            //noinspection unchecked
            var result = credentialService.presentationQueryMessage(parseBearerToken(unparsedToken), message);
            if (result.succeeded()) {
                return new HandlerResponse(200, mapper.writeValueAsString(result));
            } else {
                monitor.enableError().message(format("%s failed: %s", PRESENTATION_QUERY_MESSAGE, result.getFailure()));
                return new HandlerResponse(400, null);
            }
        } catch (IOException e) {
            throw new AssertionError(format("Error handling %s", PRESENTATION_QUERY_MESSAGE), e);
        }
    }
}

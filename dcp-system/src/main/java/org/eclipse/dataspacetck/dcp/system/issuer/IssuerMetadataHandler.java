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
import org.eclipse.dataspacetck.dcp.system.cs.CredentialObject;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_METADATA_MESSAGE_TYPE;

public class IssuerMetadataHandler implements ProtocolHandler {
    private final Map<String, CredentialObject> supportedCredentials;
    private final ObjectMapper mapper;
    private final String issuerDid;

    public IssuerMetadataHandler(Map<String, CredentialObject> supportedCredentials, ObjectMapper mapper, String issuerDid) {
        this.supportedCredentials = supportedCredentials;
        this.mapper = mapper;
        this.issuerDid = issuerDid;
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> map, InputStream inputStream) {
        var body = DcpMessageBuilder.newInstance()
                .type(ISSUER_METADATA_MESSAGE_TYPE)
                .property("issuer", issuerDid)
                .property("credentialsSupported", supportedCredentials.values())
                .build();

        try {
            var bodyJson = mapper.writeValueAsString(body);
            return new HandlerResponse(200, bodyJson);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}

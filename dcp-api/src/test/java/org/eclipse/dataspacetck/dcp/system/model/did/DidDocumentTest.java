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

package org.eclipse.dataspacetck.dcp.system.model.did;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DidDocumentTest {
    private static final String DOCUMENT = """
            {
                "@context" : [ "https://www.w3.org/ns/did/v1", "https://w3id.org/dspace-dcp/v1.0/" ],
                "id" : "did:web:localhost%3A8083:holder",
                "service" : [ {
                  "id" : "TCK-Credential-Service",
                  "type" : "CredentialService",
                  "serviceEndpoint" : "http://localhost:8083"
                } ],
                "verificationMethod" : [ {
                  "id" : "43cecd95-7a59-4a5f-b2d0-0ec73ae41a0c",
                  "type" : "JsonWebKey2020",
                  "controller" : "did:web:localhost%3A8083:holder",
                  "publicKeyJwk" : {
                    "kty" : "EC",
                    "use" : "sig",
                    "crv" : "P-256",
                    "kid" : "43cecd95-7a59-4a5f-b2d0-0ec73ae41a0c",
                    "x" : "izxXHDdzCpmt_Ivvn19qOZVhLDE29ViWPJENBJeEncA",
                    "y" : "dbn4rBSbYFbyUSbt0GzfKpxK4eODNRkWaI5LB36P9MY"
                  }
                } ]
             }""";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void verifyDeserializeSerialize() throws JsonProcessingException {
        var original = objectMapper.readValue(DOCUMENT, DidDocument.class);
        var serialized = objectMapper.writeValueAsString(original);
        var deserialized = objectMapper.readValue(serialized, DidDocument.class);
        assertThat(deserialized.getId()).isEqualTo("did:web:localhost%3A8083:holder");
        assertThat(deserialized.getServices()).allMatch(s -> s.id().equals("TCK-Credential-Service"));
        assertThat(deserialized.getVerificationMethods()).allMatch(v -> v.getId().equals("43cecd95-7a59-4a5f-b2d0-0ec73ae41a0c"));
        assertThat(deserialized.getVerificationMethod("43cecd95-7a59-4a5f-b2d0-0ec73ae41a0c")).isNotNull();
        assertThat(deserialized.getServiceEntry("CredentialService")).isNotNull();
    }
}
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
package org.eclipse.dataspacetck.dcp.verification.presentation;

import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderDid;
import org.eclipse.dataspacetck.dcp.system.annotation.Verifier;
import org.eclipse.dataspacetck.dcp.system.annotation.VerifierDid;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;

import java.time.Instant;
import java.util.Date;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;

/**
 * Skeleton test.
 */
@ExtendWith(SystemBootstrapExtension.class)
public class PresentationFlow01Test {
    @Inject
    protected CredentialService credentialService;

    @Inject
    @VerifierDid
    protected String verifierDid;

    @Inject
    @HolderDid
    protected String holderDid;

    @Inject
    @Verifier
    protected KeyService verifierKeyService;

    @MandatoryTest
    @DisplayName("Test verify")
    public void cs_01_01() {
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(holderDid);
        var baseEndpoint = document.getServiceEntry(CREDENTIAL_SERVICE_TYPE).getServiceEndpoint();

        var request = new Request.Builder()
                .url(baseEndpoint + "/presentations/query")
                .header("Authorization", "Bearer " + verifierKeyService.sign(createToken()))
                .post(RequestBody.create(SCOPE_REQUEST, MediaType.parse("application/json")))
                .build();

        executeRequest(request, response -> {
            assertThat(response.isSuccessful())
                    .withFailMessage("Request failed: " + response.code()).isTrue();
        });
    }

    private JWTClaimsSet createToken() {
        return new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .audience(verifierDid)
                .subject(holderDid)
                .claim("jti", randomUUID())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();
    }

    private static final String SCOPE_REQUEST = """
            {
              "@context": [
                "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"
              ],
              "type": "PresentationQueryMessage",
              "scope": [
                "presentation1",
                "presentation2"
              ]
            }""";

}


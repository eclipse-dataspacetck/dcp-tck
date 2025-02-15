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

package org.eclipse.dataspacetck.dcp.system.generation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyServiceImpl;
import org.eclipse.dataspacetck.dcp.system.crypto.Keys;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;

class JwtCredentialGeneratorTest {
    private static final String ISSUER_DID = "did:web:localhost%3A8083:issuer";

    private JwtCredentialGenerator generator;
    private KeyServiceImpl keyService;

    @Test
    void verifyGeneration() throws ParseException, JOSEException {
        var credential = VerifiableCredential.Builder.newInstance()
                .credentialSubject(Map.of("memberLevel", "gold"))
                .id(randomUUID().toString())
                .issuanceDate(new Date().toString())
                .issuer(ISSUER_DID)
                .type(List.of("VerifiableCredential"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .build();

        var jwt = generator.generateCredential(credential);
        var parsed = SignedJWT.parse(jwt.getContent());
        var claims = parsed.getJWTClaimsSet().getClaims();

        assertThat(parsed.getHeader().getKeyID()).isEqualTo(ISSUER_DID + "#" + keyService.getPublicKey().getKeyID());
        assertThat(claims).extracting(c -> c.get("vc")).hasFieldOrProperty("credentialSubject");

        var verifier = createVerifier(keyService.getPublicKey().toECKey().toECPublicKey());
        assertThat(parsed.verify(verifier)).isTrue();
    }

    @BeforeEach
    void setUp() {
        keyService = new KeyServiceImpl(Keys.generateEcKey());
        generator = new JwtCredentialGenerator(ISSUER_DID, keyService);
    }
}
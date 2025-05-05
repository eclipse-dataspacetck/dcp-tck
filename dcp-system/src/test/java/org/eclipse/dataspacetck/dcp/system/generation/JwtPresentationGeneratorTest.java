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
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.List;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.LIST;
import static org.assertj.core.api.InstanceOfAssertFactories.MAP;
import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat.VC1_0_JWT;

class JwtPresentationGeneratorTest {
    private static final String ISSUER_DID = "did:web:localhost%3A8083:issuer";
    private static final String HOLDER_DID = "did:web:localhost%3A8083:holder";
    private static final String VERIFIER_DID = "did:web:localhost%3A8083:verifier";
    private static final String SAMPLE_VC = """
            eyJraWQiOiJkaWQ6d2ViOmxvY2FsaG9zdCUzQTgwODM6aXNzdWVyIzg0ZmE4YmVmLTc2NmQtNDMxYy04OWVlLTgxM2QyN2RjY2VjMyIsInR5
            cCI6IkpXVCIsImFsZyI6IkVTMjU2In0.eyJzdWIiOiIzYmU1NDAxMi0zNTEzLTRhZjQtYTBmMy00ZWJmNzA1ZDE5NDEiLCJuYmYiOjE3Mzkx
            OTgwMDcsImlzcyI6ImRpZDp3ZWI6bG9jYWxob3N0JTNBODA4Mzppc3N1ZXIiLCJleHAiOjE3MzkxOTgzMDcsImlhdCI6MTczOTE5ODAwNywi
            dmMiOnsiQGNvbnRleHQiOiIzYmU1NDAxMi0zNTEzLTRhZjQtYTBmMy00ZWJmNzA1ZDE5NDEiLCJpZCI6IjNiZTU0MDEyLTM1MTMtNGFmNC1h
            MGYzLTRlYmY3MDVkMTk0MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOndlYjpsb2NhbGhvc3QlM0E4
            MDgzOmlzc3VlciIsImlzc3VhbmNlRGF0ZSI6Ik1vbiBGZWIgMTAgMTU6MzM6MjcgQ0VUIDIwMjUiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJt
            ZW1iZXJMZXZlbCI6ImdvbGQifX0sImp0aSI6ImFmOGI1NzMxLWJkYjQtNGMzZS05ZjIzLWM2MzJjMmViZjI0OCJ9.00q5xQtulyFvTBmTFs6
            Uh7xb-PqDsxd6TKzvO7n0AE9uhYQGbap9634vm7AvMnfWcTqaRV02HZbHCyJ21aFkHg""";
    private JwtPresentationGenerator generator;
    private KeyServiceImpl keyService;

    @BeforeEach
    void setUp() {
        keyService = new KeyServiceImpl(Keys.generateEcKey());
        generator = new JwtPresentationGenerator(ISSUER_DID, keyService);
    }

    @Test
    void verifyGeneration() throws ParseException, JOSEException {
        var credential = VerifiableCredential.Builder.newInstance().id(randomUUID().toString()).build();
        var container = new VcContainer(SAMPLE_VC, credential, VC1_0_JWT);
        var jwt = generator.generatePresentation(VERIFIER_DID, HOLDER_DID, List.of(container));
        var parsed = SignedJWT.parse(jwt.getContent());
        var claims = parsed.getJWTClaimsSet().getClaims();

        assertThat(parsed.getHeader().getKeyID()).isEqualTo(ISSUER_DID + "#" + keyService.getPublicKey().getKeyID());

        assertThat(claims.get("vp")).asInstanceOf(MAP).hasEntrySatisfying("verifiableCredential", credentialJwts -> {
            assertThat(credentialJwts).asInstanceOf(LIST).hasSize(1);
            assertThat(credentialJwts).asInstanceOf(LIST).first().isEqualTo(SAMPLE_VC);
        });

        var verifier = createVerifier(keyService.getPublicKey().toECKey().toECPublicKey());
        assertThat(parsed.verify(verifier)).isTrue();
    }
}
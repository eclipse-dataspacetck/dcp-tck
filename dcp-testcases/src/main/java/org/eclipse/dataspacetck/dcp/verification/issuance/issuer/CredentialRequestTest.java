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

package org.eclipse.dataspacetck.dcp.verification.issuance.issuer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderPid;
import org.eclipse.dataspacetck.dcp.system.annotation.RoleType;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.time.Instant.now;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveCredentialServiceEndpoint;

public class CredentialRequestTest extends AbstractCredentialIssuanceTest {

    @Inject
    @HolderPid
    private String holderPid;

    @MandatoryTest
    @DisplayName("6.4.1 IssuerService should accept a CredentialRequest")
    void is_6_4_1_credentialRequest(CredentialService credentialService) {

        var msg = createCredentialRequestMessage(holderPid).build();
        var token = createToken(createClaims().build());

        var request = createHttpRequest(token, msg);
        executeRequest(request.build(), response -> assertThat(response.code()).isEqualTo(201));

        await()
                .atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(500))
                .untilAsserted((() -> assertThat(credentialService.getCredentials())
                        .withFailMessage("Expected to receive a CredentialMessage")
                        .hasSize(2)));
    }


    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest without an Authorization header")
    void is_6_4_credentialRequest_noAuthHeader() {
        var msg = createCredentialRequestMessage(holderDid).build();
        var request = createHttpRequest(null, msg);

        executeRequest(request.build(), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest where the auth header does not have a Bearer prefix")
    void is_6_4_credentialRequest_noBearerPrefix() {
        var credentialMessage = createCredentialRequestMessage(holderPid).build();
        var token = createToken(createClaims().build());

        var request = createHttpRequest(null, credentialMessage)
                .header("Authorization", token)
                .build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid body")
    void is_6_4_credentialRequest_invalidBody() {
        var credentialMessage = createCredentialRequestMessage(holderPid).build();

        var invalidMessage = new HashMap<>(credentialMessage);
        invalidMessage.remove("credentials");
        var token = createToken(createClaims().build());

        var request = createHttpRequest(token, invalidMessage).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - wrong signature")
    void is_6_4_credentialRequest_tokenSignedWithWrongKey() throws JOSEException {
        var msg = createCredentialRequestMessage(holderPid).build();

        var claims = createClaims().build();
        var kid = holderKeyService.getPublicKey().getKeyID();
        var spoofedKey = new ECKeyGenerator(Curve.P_256)
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        var header = new JWSHeader.Builder(ES256).type(JWT);
        header.keyID(claims.getClaim("iss") + "#" + spoofedKey.getKeyID());

        var signedJwt = new SignedJWT(header.build(), claims);
        signedJwt.sign(new ECDSASigner(spoofedKey.toECPrivateKey()));
        var token = signedJwt.serialize();

        var request = createHttpRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - expired")
    void is_6_4_credentialRequest_tokenExpired() {
        var token = createToken(createClaims()
                .expirationTime(Date.from(now().minusSeconds(60)))
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createHttpRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - iat in future")
    void is_6_4_credentialRequest_iatInFuture() {
        var token = createToken(createClaims()
                .issueTime(Date.from(now().plusSeconds(60)))
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createHttpRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - nbf in future")
    void is_6_4_credentialRequest_nbfViolated() {
        var token = createToken(createClaims()
                .notBeforeTime(Date.from(now().plusSeconds(60)))
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createHttpRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - incorrect aud")
    void is_6_4_credentialRequest_invalidAud(@Did(RoleType.THIRD_PARTY) String thirdPartyDid) {
        var token = createToken(createClaims()
                .audience(thirdPartyDid)
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createHttpRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - iss != sub")
    void is_6_4_credentialRequest_issNotEqualSub(@Did(RoleType.THIRD_PARTY) String thirdPartyDid) {
        var token = createToken(createClaims()
                .issuer(thirdPartyDid)
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createHttpRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with an invalid token - jti already used")
    void is_6_4_credentialRequest_jtiAlreadyUsed() {
        var token = createToken(createClaims().build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createHttpRequest(token, msg).build();
        executeRequest(request, response -> assertThat(response.code()).isEqualTo(201));
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4 IssuerService should reject a CredentialRequest with a missing holderPid")
    void is_6_4_credentialRequest_missingHolderPid() {
        var token = createToken(createClaims().build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var invalidMessage = new HashMap<>(msg);
        invalidMessage.remove("holderPid");
        var request = createHttpRequest(token, invalidMessage).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    private Request.Builder createHttpRequest(String authToken, Map<String, Object> msg) {
        var endpoint = resolveCredentialServiceEndpoint(holderDid);
        try {
            var builder = new Request.Builder()
                    .url(endpoint + CREDENTIAL_REQUEST_PATH)
                    .post(RequestBody.create(mapper.writeValueAsString(msg), MediaType.parse("application/json")));
            if (authToken != null) {
                builder.addHeader(AUTHORIZATION, "Bearer " + authToken);
            }
            return builder;
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }
}

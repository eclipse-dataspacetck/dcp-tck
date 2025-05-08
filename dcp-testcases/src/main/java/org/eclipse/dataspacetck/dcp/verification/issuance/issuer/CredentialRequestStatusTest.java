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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.Request;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderPid;
import org.eclipse.dataspacetck.dcp.system.annotation.RoleType;
import org.eclipse.dataspacetck.dcp.system.issuer.CredentialStatus;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.Date;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.time.Instant.now;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_STATUS_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.assert2xxCode;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.bodyAs;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequestAndGet;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveIssuerServiceEndpoint;

public class CredentialRequestStatusTest extends AbstractCredentialIssuanceTest {
    @Inject
    @HolderPid
    private String holderPid;

    @MandatoryTest
    @DisplayName("6.8.1 IssuerService should respond with a status message")
    void is_6_8_1_credentialStatusRequest() {
        var id = requestCredentials();

        // make and assert credential status request
        var rq = createStatusRequest(id);

        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofSeconds(1))
                .untilAsserted(() -> executeRequest(rq.build(), response -> {
                    assert2xxCode(response);
                    var status = bodyAs(response, CredentialStatus.class, mapper).getStatus();
                    assertThat(status).isIn("ISSUED", "RECEIVED", "REJECTED");
                }));
    }


    @MandatoryTest
    @DisplayName("6.8.2 IssuerService should reject a CredentialRequest without an Authorization header")
    void is_6_8_2_credentialStatusRequest_noAuthHeader() {
        var id = requestCredentials();

        var rq = createStatusRequest(id)
                .removeHeader("Authorization")
                .build();

        executeRequest(rq, TestFixtures::assert4xxCode);
    }


    @MandatoryTest
    @DisplayName("6.8.3 IssuerService should reject a CredentialRequest where the auth header does not have a Bearer prefix")
    void is_6_8_3_credentialStatusRequest_noBearerPrefix() {
        var id = requestCredentials();
        var token = createToken(createClaims().build());

        var request = createStatusRequest(id, token)
                .header("Authorization", token)
                .build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }


    @MandatoryTest
    @DisplayName("6.8.5 IssuerService should reject a CredentialRequest with an invalid token - wrong signature")
    void is_6_8_5_credentialStatusRequest_tokenSignedWithWrongKey() throws JOSEException {
        var id = requestCredentials();

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

        var request = createStatusRequest(id, token)
                .build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.8.6 IssuerService should reject a CredentialRequest with an invalid token - expired")
    void is_6_8_6_credentialStatusRequest_tokenExpired() {
        var id = requestCredentials();
        var token = createToken(createClaims()
                .expirationTime(Date.from(now().minusSeconds(60)))
                .build());
        var request = createStatusRequest(id, token)
                .build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }


    @MandatoryTest
    @DisplayName("6.8.7 IssuerService should reject a CredentialRequest with an invalid token - iat in future")
    void is_6_8_7_credentialStatusRequest_iatInFuture() {
        var id = requestCredentials();
        var token = createToken(createClaims()
                .issueTime(Date.from(now().plusSeconds(60)))
                .build());
        var request = createStatusRequest(id, token).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.8.8 IssuerService should reject a CredentialRequest with an invalid token - nbf in future")
    void is_6_8_8_credentialStatusRequest_nbfViolated() {
        var id = requestCredentials();
        var token = createToken(createClaims()
                .notBeforeTime(Date.from(now().plusSeconds(60)))
                .build());
        var request = createStatusRequest(id, token).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.8.9 IssuerService should reject a CredentialRequest with an invalid token - incorrect aud")
    void is_6_8_8_credentialStatusRequest_invalidAud(@Did(RoleType.THIRD_PARTY) String thirdPartyDid) {
        var id = requestCredentials();

        var token = createToken(createClaims()
                .audience(thirdPartyDid)
                .build());
        var request = createStatusRequest(id, token).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.8.10 IssuerService should reject a CredentialRequest with an invalid token - iss != sub")
    void is_6_8_10_credentialStatusRequest_issNotEqualSub(@Did(RoleType.THIRD_PARTY) String thirdPartyDid) {
        var id = requestCredentials();

        var token = createToken(createClaims()
                .issuer(thirdPartyDid)
                .build());
        var request = createStatusRequest(id, token).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }


    @MandatoryTest
    @DisplayName("6.8.11 IssuerService should reject a CredentialRequest with an invalid token - jti already used")
    void is_6_8_11_credentialStatusRequest_jtiAlreadyUsed() {
        var id = requestCredentials();
        var token = createToken(createClaims().build());
        var request = createStatusRequest(id, token).build();
        executeRequest(request, TestFixtures::assert2xxCode);
        executeRequest(request, TestFixtures::assert4xxCode);
    }


    @MandatoryTest
    @DisplayName("6.8.12 IssuerService should respond with 4xx if the request ID is not found")
    void is_6_8_12_credentialStatusRequest_requestIdNotFound() {
        var token = createToken(createClaims().build());
        var request = createStatusRequest("not-exist", token).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @NotNull
    private Request.Builder createStatusRequest(String id) {
        return new Request.Builder()
                .url(resolveIssuerServiceEndpoint(issuerDid) + CREDENTIAL_STATUS_PATH + id)
                .header("Authorization", "Bearer " + createToken(createClaims().build()))
                .get();
    }

    @NotNull
    private Request.Builder createStatusRequest(String id, String token) {
        return new Request.Builder()
                .url(resolveIssuerServiceEndpoint(issuerDid) + CREDENTIAL_STATUS_PATH + id)
                .header("Authorization", "Bearer " + token)
                .get();
    }

    private String requestCredentials() {
        var msg = createCredentialRequestMessage(holderPid).build();
        var token = createToken(createClaims().build());

        // make credential request
        var request = createCredentialRequest(token, msg).build();
        return executeRequestAndGet(request, response -> {
            assert2xxCode(response);
            var location = response.headers().get("Location");
            assertThat(location).isNotNull();
            return location.substring(location.lastIndexOf('/') + 1);
        });
    }
}

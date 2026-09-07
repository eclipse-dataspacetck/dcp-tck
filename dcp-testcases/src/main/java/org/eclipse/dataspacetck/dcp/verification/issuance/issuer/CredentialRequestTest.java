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
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.issuer.CredentialStatus;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.time.Instant.now;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequestAndGet;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveIssuerServiceEndpoint;

public class CredentialRequestTest extends AbstractCredentialIssuanceTest {

    @Inject
    @HolderPid
    private String holderPid;

    @MandatoryTest
    @DisplayName("6.4.1 IssuerService should accept a CredentialRequest")
    void is_6_4_1_credentialRequest(CredentialService credentialService) {

        var msg = createCredentialRequestMessage(holderPid).build();
        var token = createToken(createClaims().build());

        var request = createCredentialRequest(token, msg);
        executeRequest(request.build(), response -> {
            TestFixtures.assert2xxCode(response);
            assertThat(response.header("Location")).isNotEmpty();
        });

        // wait until the IssuerService has processed the request and sends a CredentialMessage
        // to the StorageApi
        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(500))
                .untilAsserted((() -> assertThat(credentialService.getCredentials())
                        .withFailMessage("Expected to receive a CredentialMessage")
                        .hasSize(2)));
    }

    @MandatoryTest
    @DisplayName("6.4.2 IssuerService should reject a CredentialRequest without an Authorization header")
    void is_6_4_2_credentialRequest_noAuthHeader() {
        var msg = createCredentialRequestMessage(holderDid).build();
        var request = createCredentialRequest(null, msg);

        executeRequest(request.build(), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.3 IssuerService should reject a CredentialRequest where the auth header does not have a Bearer prefix")
    void is_6_4_3_credentialRequest_noBearerPrefix() {
        var credentialMessage = createCredentialRequestMessage(holderPid).build();
        var token = createToken(createClaims().build());

        var request = createCredentialRequest(null, credentialMessage)
                .header("Authorization", token)
                .build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.4 IssuerService should reject a CredentialRequest with an invalid body")
    void is_6_4_4_credentialRequest_invalidBody() {
        var credentialMessage = createCredentialRequestMessage(holderPid).build();

        var invalidMessage = new HashMap<>(credentialMessage);
        invalidMessage.remove("credentials");
        var token = createToken(createClaims().build());

        var request = createCredentialRequest(token, invalidMessage).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.5 IssuerService should reject a CredentialRequest with an invalid token - wrong signature")
    void is_6_4_5_credentialRequest_tokenSignedWithWrongKey() throws JOSEException {
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

        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.6 IssuerService should reject a CredentialRequest with an invalid token - expired")
    void is_6_4_6_credentialRequest_tokenExpired() {
        var token = createToken(createClaims()
                .expirationTime(Date.from(now().minusSeconds(60)))
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.7 IssuerService should reject a CredentialRequest with an invalid token - iat in future")
    void is_6_4_7_credentialRequest_iatInFuture() {
        var token = createToken(createClaims()
                .issueTime(Date.from(now().plusSeconds(60)))
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.8 IssuerService should reject a CredentialRequest with an invalid token - nbf in future")
    void is_6_4_8_credentialRequest_nbfViolated() {
        var token = createToken(createClaims()
                .notBeforeTime(Date.from(now().plusSeconds(60)))
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.9 IssuerService should reject a CredentialRequest with an invalid token - incorrect aud")
    void is_6_4_9_credentialRequest_invalidAud(@Did(RoleType.THIRD_PARTY) String thirdPartyDid) {
        var token = createToken(createClaims()
                .audience(thirdPartyDid)
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.10 IssuerService should reject a CredentialRequest with an invalid token - iss != sub")
    void is_6_4_10_credentialRequest_issNotEqualSub(@Did(RoleType.THIRD_PARTY) String thirdPartyDid) {
        var token = createToken(createClaims()
                .issuer(thirdPartyDid)
                .build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.11 IssuerService should reject a CredentialRequest with an invalid token - jti already used")
    void is_6_4_11_credentialRequest_jtiAlreadyUsed() {
        var token = createToken(createClaims().build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var request = createCredentialRequest(token, msg).build();
        executeRequest(request, response -> assertThat(response.code()).isEqualTo(201));
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 IssuerService should reject a CredentialRequest - kid resolves to no verification method")
    void is_4_3_3_credentialRequest_unknownKid() {
        var msg = createCredentialRequestMessage(holderPid).build();
        var token = createTokenWithUnknownKid(createClaims().build());

        executeRequest(createCredentialRequest(token, msg).build(), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 IssuerService should reject a CredentialRequest - sub DID is not resolvable")
    void is_4_3_3_credentialRequest_unresolvableSubject() {
        var msg = createCredentialRequestMessage(holderPid).build();
        var token = createTokenWithUnresolvableSubject(createClaims());

        executeRequest(createCredentialRequest(token, msg).build(), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.1 IssuerService should reject a CredentialRequest with an empty credentials array")
    void is_6_4_1_credentialRequest_emptyCredentials() {
        var msg = new HashMap<>(createCredentialRequestMessage(holderPid).build());
        msg.put("credentials", List.of());

        var token = createToken(createClaims().build());
        executeRequest(createCredentialRequest(token, msg).build(), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.4.1 IssuerService must not silently accept a request for an unsupported credential")
    void is_6_4_1_credentialRequest_unsupportedCredentialId() {
        var msg = new HashMap<>(createCredentialRequestMessage(holderPid).build());
        msg.put("credentials", List.of(Map.of("id", "unsupported-" + randomUUID())));

        var token = createToken(createClaims().build());

        // the issuer may reject synchronously, or accept and report the failure through the status endpoint,
        // but it must never report the request as issued
        var location = executeRequestAndGet(createCredentialRequest(token, msg).build(), response -> {
            if (!response.isSuccessful()) {
                assertThat(response.code()).isBetween(400, 499);
                return null;
            }
            return response.header("Location");
        });

        if (location == null) {
            return;
        }

        var statusRequest = new Request.Builder()
                .url(absoluteLocation(location))
                .header(AUTHORIZATION, "Bearer " + createToken(createClaims().build()))
                .get()
                .build();

        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofSeconds(1))
                .untilAsserted(() -> executeRequest(statusRequest, response -> {
                    if (!response.isSuccessful()) {
                        assertThat(response.code()).isBetween(400, 499);
                        return;
                    }
                    var status = TestFixtures.bodyAs(response, CredentialStatus.class, mapper).getStatus();
                    assertThat(status)
                            .withFailMessage("A request for an unsupported credential must not be reported as ISSUED")
                            .isEqualTo("REJECTED");
                }));
    }

    @MandatoryTest
    @DisplayName("6.4.1 IssuerService should not issue twice for a repeated holderPid")
    void is_6_4_1_credentialRequest_duplicateHolderPid(CredentialService credentialService) {
        var msg = createCredentialRequestMessage(holderPid).build();

        executeRequest(createCredentialRequest(createToken(createClaims().build()), msg).build(),
                TestFixtures::assert2xxCode);

        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(500))
                .untilAsserted(() -> assertThat(credentialService.getReceivedCredentialMessages()).hasSize(1));

        // a second request carrying the same holderPid identifies the same logical request: the issuer may reject it
        // or treat it idempotently, but it must not issue a second time
        executeRequest(createCredentialRequest(createToken(createClaims().build()), msg).build(),
                response -> assertThat(response.code()).isBetween(200, 499));

        assertThat(credentialService.getReceivedCredentialMessages())
                .withFailMessage("A repeated holderPid must not trigger a second issuance")
                .hasSize(1);
    }

    @MandatoryTest
    @DisplayName("6.4.12 IssuerService should reject a CredentialRequest with a missing holderPid")
    void is_6_4_12_credentialRequest_missingHolderPid() {
        var token = createToken(createClaims().build());
        var msg = createCredentialRequestMessage(holderPid).build();
        var invalidMessage = new HashMap<>(msg);
        invalidMessage.remove("holderPid");
        var request = createCredentialRequest(token, invalidMessage).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    /**
     * The Location header may be absolute or relative to the IssuerService endpoint.
     */
    private String absoluteLocation(String location) {
        return location.startsWith("http") ? location : resolveIssuerServiceEndpoint(issuerDid) + location;
    }
}

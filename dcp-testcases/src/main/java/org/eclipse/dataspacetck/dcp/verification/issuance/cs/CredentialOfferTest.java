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

package org.eclipse.dataspacetck.dcp.verification.issuance.cs;

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
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.time.Instant.now;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.THIRD_PARTY;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_OFFER_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.OFFERS_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveCredentialServiceEndpoint;

/**
 * Verifies Credential Offer messages testing the CredentialService as system-under-test.
 */
public class CredentialOfferTest extends AbstractCredentialIssuanceTest {

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService should accept CredentialOfferMessage")
    void cs_06_06_01_credentialOfferMessage() {
        var msg = createCredentialOfferMessage().build();

        var token = createToken(createClaims().build());
        var request = createCredentialOfferMessageRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert2xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService should accept CredentialOfferMessage (only IDs)")
    void cs_06_06_01_credentialOfferMessage_onlyIds() {
        var msg = createCredentialOfferMessage()
                .property("credentials", List.of(
                        Map.of("id", UUID.randomUUID().toString()),
                        Map.of("id", UUID.randomUUID().toString())
                ))
                .build();

        var token = createToken(createClaims().build());
        var request = createCredentialOfferMessageRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert2xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects a CredentialOfferMessage with no auth header")
    void cs_06_06_01_credentialOfferMessage_noAuthHeader() {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var request = createCredentialOfferMessageRequest(null, credentialOfferMessage).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects a CredentialOfferMessage where the auth header has no bearer prefix")
    void cs_06_06_01_credentialOfferMessage_missingBearerPrefix() {
        var credentialOfferMessage = createCredentialOfferMessage().build();
        var token = createToken(createClaims().build());

        var request = createCredentialOfferMessageRequest(null, credentialOfferMessage)
                .header("Authorization", token)
                .build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects a CredentialOfferMessage with an invalid message body")
    void cs_06_06_01_credentialOfferMessage_invalidBody() {
        var message = createCredentialOfferMessage()
                .property("issuer", null)
                .build();

        var invalidMessage = new HashMap<>(message);
        invalidMessage.remove("holderPid");
        var token = createToken(createClaims().build());

        var request = createCredentialOfferMessageRequest(token, invalidMessage).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - wrong signing key")
    void cs_06_06_01_credentialOfferMessage_tokenSignedWithWrongKey() throws JOSEException {
        var msg = createCredentialOfferMessage().build();

        var claims = createClaims().build();
        var kid = issuerKeyService.getPublicKey().getKeyID();
        var spoofedKey = new ECKeyGenerator(Curve.P_256)
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        var header = new JWSHeader.Builder(ES256).type(JWT);
        header.keyID(claims.getClaim("iss") + "#" + spoofedKey.getKeyID());

        var signedJwt = new SignedJWT(header.build(), claims);
        signedJwt.sign(new ECDSASigner(spoofedKey.toECPrivateKey()));
        var token = signedJwt.serialize();

        var request = createCredentialOfferMessageRequest(token, msg).build();
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - token expired")
    void cs_06_06_01_credentialOfferMessage_tokenExpired() {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var token = createToken(createClaims().expirationTime(Date.from(now().minus(1, ChronoUnit.HOURS))).build());
        var request = createCredentialOfferMessageRequest(token, credentialOfferMessage).build();

        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - iat in the future")
    void cs_06_06_01_credentialOfferMessage_iatInFuture() {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var token = createToken(createClaims().issueTime(Date.from(now().plus(1, ChronoUnit.HOURS))).build());
        var request = createCredentialOfferMessageRequest(token, credentialOfferMessage).build();

        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - nbf")
    void cs_06_06_01_credentialOfferMessage_nbfViolated() {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var token = createToken(createClaims().notBeforeTime(Date.from(now().plus(1, ChronoUnit.HOURS))).build());
        var request = createCredentialOfferMessageRequest(token, credentialOfferMessage).build();

        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - incorrect aud")
    void cs_06_06_01_credentialOfferMessage_incorrectAudience(@Did(THIRD_PARTY) String thirdPartyDid) {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var token = createToken(createClaims().audience(thirdPartyDid).build());
        var request = createCredentialOfferMessageRequest(token, credentialOfferMessage).build();

        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - iss != sub")
    void cs_06_06_01_credentialOfferMessage_issNotEqualToSub(@Did(THIRD_PARTY) String thirdPartyDid) {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var token = createToken(createClaims()
                .issuer(issuerDid)
                .subject(thirdPartyDid)
                .build());
        var request = createCredentialOfferMessageRequest(token, credentialOfferMessage).build();

        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("6.6.1 CredentialService rejects an invalid auth token - jti used before")
    void cs_06_06_01_credentialOfferMessage_jtiAlreadyUsed() {
        var credentialOfferMessage = createCredentialOfferMessage().build();

        var token = createToken(createClaims().build());
        var request = createCredentialOfferMessageRequest(token, credentialOfferMessage).build();

        executeRequest(request, response -> assertThat(response.isSuccessful()).isTrue());
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    private Request.Builder createCredentialOfferMessageRequest(String authToken, Map<String, Object> credentialOfferMessage) {
        var endpoint = resolveCredentialServiceEndpoint(holderDid);
        try {
            var builder = new Request.Builder()
                    .url(endpoint + OFFERS_PATH)
                    .post(RequestBody.create(mapper.writeValueAsString(credentialOfferMessage), MediaType.parse("application/json")));
            if (authToken != null) {
                builder.addHeader(AUTHORIZATION, "Bearer " + authToken);
            }
            return builder;
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    private DcpMessageBuilder createCredentialOfferMessage() {
        return DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_OFFER_MESSAGE_TYPE)
                .property("issuer", issuerDid)
                .property("credentials", List.of(
                        Map.of("id", UUID.randomUUID().toString(),
                                "type", "CredentialObject",
                                "credentialType", "MembershipCredential",
                                "offerReason", "reissue",
                                "bindingMethods", List.of("did:web:"),
                                "profiles", List.of("vc11-sl2021/jwt", "vc20-bssl/jwt"),
                                "issuancePolicy", Map.of()) //fixme: add issuance policy
                ));
    }

}

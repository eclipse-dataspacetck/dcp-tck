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

import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderPid;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;

import java.text.ParseException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VC;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.assertCredentialMessageEnvelope;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.parseAndVerifySelfIssuedToken;

/**
 * Verifies what the IssuerService actually delivers to the holder's Storage API after accepting a CredentialRequest.
 * <p>
 * The TCK hosts a CredentialService, so the delivery arrives here and can be inspected: the message envelope, the
 * self-issued token it was sent with, and the credentials themselves.
 */
public class CredentialDeliveryTest extends AbstractCredentialIssuanceTest {

    private static final Duration DELIVERY_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(500);

    @Inject
    @HolderPid
    private String holderPid;

    @MandatoryTest
    @DisplayName("6.5.1 IssuerService should deliver a well-formed CredentialMessage correlated with the request")
    void is_6_5_1_credentialDelivery_envelope(CredentialService credentialService) {
        requestCredentials();

        var message = awaitSingleDelivery(credentialService).message();

        assertCredentialMessageEnvelope(message, holderPid, "ISSUED");
        assertThat(credentialContainers(message))
                .withFailMessage("Expected the delivery to carry at least one credential")
                .isNotEmpty();
    }

    @MandatoryTest
    @DisplayName("6.5.1 IssuerService should deliver all requested credentials in a single CredentialMessage")
    void is_6_5_1_credentialDelivery_singleMessageForBatch(CredentialService credentialService) {
        var requestedCount = requestCredentials();

        // a request for multiple credentials must be fulfilled by exactly one CredentialMessage, not one per credential
        var delivery = awaitSingleDelivery(credentialService);

        assertThat(credentialContainers(delivery.message()))
                .withFailMessage("Expected all %s requested credentials in a single CredentialMessage", requestedCount)
                .hasSize(requestedCount);
    }

    @MandatoryTest
    @DisplayName("4.3 IssuerService should sign the credential delivery with a valid self-issued token")
    void is_4_3_credentialDelivery_selfIssuedToken(CredentialService credentialService) {
        requestCredentials();

        var delivery = awaitSingleDelivery(credentialService);

        // iss == sub == issuer DID, aud == holder DID, signed by a key resolvable in the issuer's DID document
        parseAndVerifySelfIssuedToken(delivery.idToken(), issuerDid, holderDid);
    }

    @MandatoryTest
    @DisplayName("6.1 IssuerService should echo the holder's access token in the delivery token")
    void is_6_1_credentialDelivery_echoesAccessToken(CredentialService credentialService) {
        var accessToken = "tck-access-token-" + randomUUID();

        requestCredentials(accessToken);

        var delivery = awaitSingleDelivery(credentialService);
        var claims = parseAndVerifySelfIssuedToken(delivery.idToken(), issuerDid, holderDid);

        assertThat(claims.getClaim(TOKEN))
                .withFailMessage("Expected the delivery token to echo the access token issued by the holder")
                .isEqualTo(accessToken);
    }

    @MandatoryTest
    @DisplayName("6.5.2 IssuerService should deliver verifiable credentials bound to the holder")
    void is_6_5_2_credentialDelivery_credentialsVerify(CredentialService credentialService) {
        requestCredentials();

        var delivery = awaitSingleDelivery(credentialService);

        for (var container : credentialContainers(delivery.message())) {
            var format = container.get("format");
            assertThat(Arrays.stream(CredentialFormat.values()).map(f -> f.profileString))
                    .withFailMessage("Delivered credential declares an unknown format: %s", format)
                    .contains((String) format);

            var payload = (String) container.get("payload");
            assertThat(payload).withFailMessage("Delivered credential has no payload").isNotNull();

            // verifies the proof against the signing key resolved from the issuer's DID document
            var types = TestFixtures.parseAndVerifyCredentials(List.of(payload)).toList();
            assertThat(types).contains("VerifiableCredential", (String) container.get("credentialType"));

            var credential = credentialClaim(payload);
            assertThat(credential.get("issuer")).satisfiesAnyOf(
                    issuer -> assertThat(issuer).isEqualTo(issuerDid),
                    issuer -> assertThat(((Map<?, ?>) issuer).get("id")).isEqualTo(issuerDid));

            @SuppressWarnings("unchecked")
            var subject = (Map<String, Object>) credential.get("credentialSubject");
            assertThat(subject.get("id"))
                    .withFailMessage("Expected credentialSubject.id to be bound to the holder DID '%s' but was '%s'",
                            holderDid, subject.get("id"))
                    .isEqualTo(holderDid);
        }
    }

    /**
     * Sends a CredentialRequestMessage for every credential the issuer supports under the tested profile and returns
     * the number of credentials requested.
     */
    private int requestCredentials() {
        return requestCredentials(null);
    }

    private int requestCredentials(String accessToken) {
        var messageBuilder = createCredentialRequestMessage(holderPid);
        var message = messageBuilder.build();

        var claims = createClaims();
        if (accessToken != null) {
            claims.claim(TOKEN, accessToken);
        }

        var request = createCredentialRequest(createToken(claims.build()), message);
        executeRequest(request.build(), TestFixtures::assert2xxCode);

        @SuppressWarnings("unchecked")
        var credentials = (Collection<?>) message.get("credentials");
        return credentials.size();
    }

    private CredentialService.ReceivedCredentialMessage awaitSingleDelivery(CredentialService credentialService) {
        await().atMost(DELIVERY_TIMEOUT)
                .pollInterval(POLL_INTERVAL)
                .untilAsserted(() -> assertThat(credentialService.getReceivedCredentialMessages())
                        .withFailMessage("Expected the IssuerService to deliver exactly one CredentialMessage")
                        .hasSize(1));
        return credentialService.getReceivedCredentialMessages().iterator().next();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> credentialContainers(Map<String, Object> message) {
        return (List<Map<String, Object>>) message.get("credentials");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> credentialClaim(String payload) {
        try {
            return (Map<String, Object>) SignedJWT.parse(payload).getJWTClaimsSet().getClaim(VC);
        } catch (ParseException e) {
            throw new AssertionError(e);
        }
    }
}

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

package org.eclipse.dataspacetck.dcp.verification.presentation.verifier;

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.dcp.system.annotation.AuthToken;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.IssueCredentials;
import org.eclipse.dataspacetck.dcp.system.annotation.ThirdParty;
import org.eclipse.dataspacetck.dcp.system.annotation.TriggerEndpoint;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;

import java.util.Date;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.THIRD_PARTY;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_SCOPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;


/**
 * Verifies ID token validation for the Credential Service.
 */
public class PresentationFlowSection4Test extends AbstractVerifierPresentationFlowTest {

    @Inject
    @ThirdParty
    private KeyService thirdPartyKeyService;

    @DisplayName("Verifier should reject an auth token without the Bearer prefix")
    @MandatoryTest
    void presentationResponse_rejectMissingBearerPrefix(@TriggerEndpoint String triggerEndpoint,
                                                        @AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var triggerMessage = createTriggerMessage();

        var rq = createRequest(triggerEndpoint, createIdToken(authToken), triggerMessage);
        executeRequest(rq, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - auth token bound to a different iss/sub")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenInvalidIssuerSub(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                    @TriggerEndpoint String triggerEndpoint,
                                                    @Did(THIRD_PARTY) String thirdPartyDid) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(thirdPartyDid)     // iss and sub diff than the auth token binding to the verifier
                .subject(thirdPartyDid)
                .audience(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        var idToken = "Bearer " + thirdPartyKeyService.sign(emptyMap(), claimSet);

        var msg = createTriggerMessage();
        var request = createRequest(triggerEndpoint, idToken, msg);
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - iss and sub different")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenInvalidSub(@AuthToken(MEMBERSHIP_SCOPE) String authToken, @TriggerEndpoint String triggerEndpoint, @Did(THIRD_PARTY) String thirdPartyDid) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(thirdPartyDid)  // invalid subject
                .audience(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        var authHeader = "Bearer " + holderKeyService.sign(emptyMap(), claimSet);
        executeRequest(createRequest(triggerEndpoint, authHeader, createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - incorrect aud")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenIncorrectAud(@AuthToken(MEMBERSHIP_SCOPE) String authToken, @TriggerEndpoint String triggerEndpoint, @Did(THIRD_PARTY) String thirdPartyDid) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(holderDid)
                .audience(thirdPartyDid)  // invalid audience
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        var authHeader = "Bearer " + holderKeyService.sign(emptyMap(), claimSet);
        executeRequest(createRequest(triggerEndpoint, authHeader, createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - sub does not match DID document id")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenIncorrectSub(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                      @TriggerEndpoint String triggerEndpoint,
                                                      @Did(THIRD_PARTY) String thirdPartyDid) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(thirdPartyDid)    // invalid subject
                .audience(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        var authHeader = "Bearer " + holderKeyService.sign(emptyMap(), claimSet);
        executeRequest(createRequest(triggerEndpoint, authHeader, createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - nbf in future")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenNbfInFuture(@AuthToken(MEMBERSHIP_SCOPE) String authToken, @TriggerEndpoint String triggerEndpoint) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(holderDid)
                .audience(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .notBeforeTime(Date.from(now().plusSeconds(1000000)))  // in future
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        var authHeader = "Bearer " + holderKeyService.sign(emptyMap(), claimSet);
        executeRequest(createRequest(triggerEndpoint, authHeader, createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - expired")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenExpired(@AuthToken(MEMBERSHIP_SCOPE) String authToken, @TriggerEndpoint String triggerEndpoint) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(holderDid)
                .audience(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().minusSeconds(1000000))) // in past
                .claim(TOKEN, authToken)
                .build();

        var authHeader = "Bearer " + holderKeyService.sign(emptyMap(), claimSet);
        executeRequest(createRequest(triggerEndpoint, authHeader, createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - jti")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void verifier_04_03_03_idTokenJtiUsedTwice(@AuthToken(MEMBERSHIP_SCOPE) String authToken1,
                                                @AuthToken(MEMBERSHIP_SCOPE) String authToken2,
                                                @TriggerEndpoint String triggerEndpoint) {
        var jti = randomUUID().toString();
        var claimSet1 = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(holderDid)
                .audience(verifierDid)
                .jwtID(jti)
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken1)
                .build();

        var authHeader1 = "Bearer " + holderKeyService.sign(emptyMap(), claimSet1);
        executeRequest(createRequest(triggerEndpoint, authHeader1, createTriggerMessage()), TestFixtures::assert2xxCode);

        var claimSet2 = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(holderDid)
                .audience(verifierDid)
                .jwtID(jti)
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken2)
                .build();

        var authHeader2 = "Bearer " + holderKeyService.sign(emptyMap(), claimSet2);
        executeRequest(createRequest(triggerEndpoint, authHeader2, createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @DisplayName("4.3.1 Verifier should reject an ID token that does not contain an access token")
    @MandatoryTest
    @IssueCredentials({MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE})
    void verifier_04_03_01_presentationResponse_idTokenNoTokenClaim(@TriggerEndpoint String triggerEndpoint) {
        executeRequest(createRequest(triggerEndpoint, "Bearer " + createIdToken(null), createTriggerMessage()), TestFixtures::assert4xxCode);
    }
}

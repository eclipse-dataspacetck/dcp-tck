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

package org.eclipse.dataspacetck.dcp.verification.presentation.cs;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.dcp.system.annotation.AuthToken;
import org.eclipse.dataspacetck.dcp.system.annotation.IssueCredentials;
import org.eclipse.dataspacetck.dcp.system.message.DcpConstants;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveCredentialServiceEndpoint;


/**
 * Verifies ID token validation for the Credential Service.
 */
public class PresentationFlowSection4Test extends AbstractPresentationFlowTest {

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - auth token bound to a different iss/sub")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idTokenInvalidIssuerSub(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(thirdPartyDid)     // iss and sub diff than the auth token binding to the verifier
                .subject(thirdPartyDid)
                .audience(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        var idToken = thirdPartyKeyService.sign(emptyMap(), claimSet);

        try {
            var endpoint = resolveCredentialServiceEndpoint(holderDid);
            var request = new Request.Builder()
                    .url(endpoint + PRESENTATION_QUERY_PATH)
                    .header(DcpConstants.AUTHORIZATION, "Bearer " + idToken)
                    .post(RequestBody.create(mapper.writeValueAsString(createMessage()), MediaType.parse(DcpConstants.JSON_CONTENT_TYPE)))
                    .build();
            executeRequest(request, TestFixtures::assert4xxCode);

        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - iss and sub different")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idTokenInvalidSub(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject("did:web:another.com:subject")    // invalid subject
                .audience(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        executeRequest(createRequest(claimSet, createMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - incorrect aud")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idtokenIncorrectAud(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject(verifierDid)
                .audience(verifierDid)  // invalid audience
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        executeRequest(createRequest(claimSet, createMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - sub does not match DID document id")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idtokenIncorrectSub(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer("did:web:another.com:subject")
                .subject("did:web:another.com:subject")    // invalid subject
                .audience(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        executeRequest(createRequest(claimSet, createMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - nbf in future")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idtokenNbfInFuture(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject(verifierDid)
                .audience(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .notBeforeTime(Date.from(now().plusSeconds(1000000)))  // in future
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        executeRequest(createRequest(claimSet, createMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - expired")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idtokenExpired(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject(verifierDid)
                .audience(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().minusSeconds(1000000))) // in past
                .claim(TOKEN, authToken)
                .build();

        executeRequest(createRequest(claimSet, createMessage()), TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("4.3.3 Verify invalid access token - jti")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_04_03_03_idtokenJtiUsedTwice(@AuthToken(MEMBERSHIP_SCOPE) String authToken1,
                                                @AuthToken(MEMBERSHIP_SCOPE) String authToken2) {
        var jti = randomUUID().toString();
        var claimSet1 = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject(verifierDid)
                .audience(holderDid)
                .jwtID(jti)
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken1)
                .build();

        executeRequest(createRequest(claimSet1, createMessage()), response -> verifyCredentials(response, MEMBERSHIP_CREDENTIAL_TYPE));

        var claimSet2 = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject(verifierDid)
                .audience(holderDid)
                .jwtID(jti)
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken2)
                .build();

        executeRequest(createRequest(claimSet2, createMessage()), TestFixtures::assert4xxCode);
    }

    @NotNull
    private Request createRequest(JWTClaimsSet claimSet, Map<String, Object> message) {
        var idToken = verifierKeyService.sign(emptyMap(), claimSet);

        try {
            var endpoint = resolveCredentialServiceEndpoint(holderDid);
            return new Request.Builder()
                    .url(endpoint + PRESENTATION_QUERY_PATH)
                    .header(DcpConstants.AUTHORIZATION, "Bearer " + idToken)
                    .post(RequestBody.create(mapper.writeValueAsString(message), MediaType.parse(DcpConstants.JSON_CONTENT_TYPE)))
                    .build();
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    private Map<String, Object> createMessage() {
        return DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE))
                .build();
    }

}

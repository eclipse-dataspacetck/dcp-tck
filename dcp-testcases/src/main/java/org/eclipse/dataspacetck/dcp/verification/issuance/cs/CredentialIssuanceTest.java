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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Credential;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderPid;
import org.eclipse.dataspacetck.dcp.system.annotation.IssuanceFlow;
import org.eclipse.dataspacetck.dcp.system.annotation.Issuer;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.ISSUER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.THIRD_PARTY;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIALS_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;

/**
 * Verifies Credential Issuance messages testing the CredentialService as system-under-test.
 */
@IssuanceFlow
@ExtendWith(SystemBootstrapExtension.class)
public class CredentialIssuanceTest {
    private final ObjectMapper mapper = new ObjectMapper();
    @Inject
    @Did(ISSUER)
    protected String issuerDid;

    @Inject
    @Did(HOLDER)
    protected String holderDid;

    @Inject
    @Credential(MEMBERSHIP_CREDENTIAL_TYPE)
    private VcContainer membershipCredential;

    @Inject
    @Credential(SENSITIVE_DATA_CREDENTIAL_TYPE)
    private VcContainer sensitiveDataCredential;

    @Inject
    @Issuer
    private KeyService issuerKeyService;

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService should accept expected CredentialMessage")
    void cs_06_05_01_credentialMessage(@HolderPid String holderPid) {

        var credentialMessage = createCredentialMessage(holderPid)
                .build();

        var token = createToken(createClaims().build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();
        executeRequest(request, response -> assertThat(response.code()).isEqualTo(200));
    }


    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects a CredentialMessage with no auth header")
    void cs_06_05_01_credentialMessage_noAuthHeader(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var request = createCredentialMessageRequest(null, credentialMessage).build();
        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects a CredentialMessage where the auth header has no bearer prefix")
    void cs_06_05_01_credentialMessage_missingBearerPrefix(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();
        var token = createToken(createClaims().build());

        var request = createCredentialMessageRequest(null, credentialMessage)
                .header("Authorization", token)
                .build();
        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects a CredentialMessage with an invalid message body")
    void cs_06_05_01_credentialMessage_invalidBody(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var invalidMessage = new HashMap<>(credentialMessage);
        invalidMessage.remove("holderPid");
        var token = createToken(createClaims().build());

        var request = createCredentialMessageRequest(token, invalidMessage).build();
        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - wrong signing key")
    void cs_06_05_01_credentialMessage_tokenSignedWithWrongKey() {

    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - token expired")
    void cs_06_05_01_credentialMessage_tokenExpired(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var token = createToken(createClaims().expirationTime(Date.from(now().minus(1, ChronoUnit.HOURS))).build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - iat in the future")
    void cs_06_05_01_credentialMessage_iatInFuture(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var token = createToken(createClaims().issueTime(Date.from(now().plus(1, ChronoUnit.HOURS))).build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - nbf")
    void cs_06_05_01_credentialMessage_nbfViolated(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var token = createToken(createClaims().notBeforeTime(Date.from(now().plus(1, ChronoUnit.HOURS))).build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - incorrect aud")
    void cs_06_05_01_credentialMessage_incorrectAudience(@HolderPid String holderPid, @Did(THIRD_PARTY) String thirdPartyDid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var token = createToken(createClaims().audience(thirdPartyDid).build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - iss != sub")
    void cs_06_05_01_credentialMessage_issNotEqualToSub(@HolderPid String holderPid, @Did(THIRD_PARTY) String thirdPartyDid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var token = createToken(createClaims()
                .issuer(issuerDid)
                .subject(thirdPartyDid)
                .build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid auth token - jti used before")
    void cs_06_05_01_credentialMessage_jtiAlreadyUsed(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid).build();

        var token = createToken(createClaims().build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, response -> assertThat(response.isSuccessful()).isTrue());
        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    @MandatoryTest
    @DisplayName("6.5.1 CredentialService rejects an invalid status string")
    void cs_06_05_01_credentialMessage_invalidStatus(@HolderPid String holderPid) {
        var credentialMessage = createCredentialMessage(holderPid)
                .property("status", "INVALID_STATUS").build();

        var token = createToken(createClaims().build());
        var request = createCredentialMessageRequest(token, credentialMessage).build();

        executeRequest(request, TestFixtures::assert4xxxCode);
    }

    private JWTClaimsSet.Builder createClaims() {
        return new JWTClaimsSet.Builder()
                .audience(holderDid)
                .issuer(issuerDid)
                .subject(issuerDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)));
    }

    private String createToken(JWTClaimsSet claims) {
        return issuerKeyService.sign(emptyMap(), claims);
    }

    /**
     * Resolves the credential service endpoint from its DID.
     */
    protected String resolveCredentialServiceEndpoint() {
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(holderDid);
        return document.getServiceEntry(CREDENTIAL_SERVICE_TYPE).getServiceEndpoint();
    }

    private Request.Builder createCredentialMessageRequest(String authToken, Map<String, Object> credentialMessage) {
        var endpoint = resolveCredentialServiceEndpoint();
        try {
            var builder = new Request.Builder()
                    .url(endpoint + CREDENTIALS_PATH)
                    .post(RequestBody.create(mapper.writeValueAsString(credentialMessage), MediaType.parse("application/json")));
            if (authToken != null) {
                builder.addHeader(AUTHORIZATION, "Bearer " + authToken);
            }
            return builder;
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    private DcpMessageBuilder createCredentialMessage(String holderPid) {
        return DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_MESSAGE_TYPE)
                .property("issuerPid", UUID.randomUUID().toString())
                .property("holderPid", holderPid)
                .property("status", "ISSUED")
                .property("credentials", List.of(
                        Map.of("credentialType", MEMBERSHIP_CREDENTIAL_TYPE,
                                "format", "VC1_0_JWT",
                                "payload", membershipCredential.rawCredential()),
                        Map.of("credentialType", SENSITIVE_DATA_CREDENTIAL_TYPE,
                                "format", "VC1_0_JWT",
                                "payload", sensitiveDataCredential.rawCredential())
                ));
    }


}

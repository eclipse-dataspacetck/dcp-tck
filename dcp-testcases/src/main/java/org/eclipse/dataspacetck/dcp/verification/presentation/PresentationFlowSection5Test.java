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
package org.eclipse.dataspacetck.dcp.verification.presentation;

import com.fasterxml.jackson.core.JsonProcessingException;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.AuthToken;
import org.eclipse.dataspacetck.dcp.system.annotation.IssueCredentials;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_DEFINITION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_SCOPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.createPresentationDefinition;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;

/**
 * Presentation flow tests.
 */
@ExtendWith(SystemBootstrapExtension.class)
public class PresentationFlowSection5Test extends AbstractPresentationFlowTest {

    @MandatoryTest
    @DisplayName("5.2 Verify Credential Service endpoint discovery")
    public void cs_05_02_endpointDiscovery() {
        var didClient = new DidClient(false);
        var didDocument = didClient.resolveDocument(holderDid);
        assertThat(didDocument).isNotNull();
        assertThat(didDocument.getServiceEntry(CREDENTIAL_SERVICE_TYPE).getServiceEndpoint()).isNotNull();
    }

    @MandatoryTest
    @DisplayName("5.3.1 Verify submitting an invalid access token header")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_03_01_accessTokenInvalidHeader(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var message = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE))
                .build();

        var endpoint = resolveCredentialServiceEndpoint();
        try {
            var request = new Request.Builder()
                    .url(endpoint + PRESENTATION_QUERY_PATH)
                    .header(AUTHORIZATION, createIdToken(authToken))  // invalid auth header missing "Bearer" prefix
                    .post(RequestBody.create(mapper.writeValueAsString(message), MediaType.parse(JSON_CONTENT_TYPE)))
                    .build();
            executeRequest(request, TestFixtures::assert4XXXCode);
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    @MandatoryTest
    @DisplayName("5.4 Verify Resolution API invalid token not authorized")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_invalidTokenNotAuthorized() {
        var message = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE))
                .build();

        var request = createPresentationRequest("faketoken", message);
        executeRequest(request, TestFixtures::assert4XXXCode);
    }

    @MandatoryTest
    @DisplayName("5.4.1.2 Verify Resolution API request does not contain a scope and presentation definition")
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_01_InvalidScopeAndPresentationRequest(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var message = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE))
                .property(PRESENTATION_DEFINITION, createPresentationDefinition(MEMBERSHIP_CREDENTIAL_TYPE))
                .build();

        var request = createPresentationRequest(authToken, message);
        executeRequest(request, response -> assertThat(response.code()).isEqualTo(400));
    }

    @Disabled
    @MandatoryTest
    @DisplayName("5.4.1.1 Verify Resolution API presentation definition request for a " + MEMBERSHIP_CREDENTIAL_TYPE)
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_01_01_presentationRequest(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Disabled
    @MandatoryTest
    @DisplayName("5.4.1.2 Verify Resolution API presentation definition less types than requested for a " + SENSITIVE_DATA_CREDENTIAL_TYPE)
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_01_02_lessTypesThanAuthorizedByTypeRequest(@AuthToken({ MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE }) String authToken) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Disabled
    @MandatoryTest
    @DisplayName("5.4.1.1 Verify Resolution API presentation definition request for a " + MEMBERSHIP_CREDENTIAL_TYPE)
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_01_01_invalidPresentationEscalationRequest(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @MandatoryTest
    @DisplayName("5.4.1.2 Verify Resolution API scope request for a " + MEMBERSHIP_CREDENTIAL_TYPE)
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_01_02_scopeByTypeRequest(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var message = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE))
                .build();

        var request = createPresentationRequest(authToken, message);
        executeRequest(request, response -> verifyCredentials(response, MEMBERSHIP_CREDENTIAL_TYPE));
    }

    @MandatoryTest
    @DisplayName("5.4.1.2 Verify Resolution API with less scopes than requested for a " + SENSITIVE_DATA_CREDENTIAL_TYPE)
    @IssueCredentials(MEMBERSHIP_CREDENTIAL_TYPE)
    public void cs_05_04_01_02_lessScopesThanAuthorizedByTypeRequest(@AuthToken({ MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE }) String authToken) {
        var message = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(SENSITIVE_DATA_SCOPE))
                .build();

        var request = createPresentationRequest(authToken, message);
        executeRequest(request, response -> verifyCredentials(response, SENSITIVE_DATA_CREDENTIAL_TYPE));
    }

    @MandatoryTest
    @DisplayName("5.4.1.2 Verify Resolution API invalid scope escalation request for a " + SENSITIVE_DATA_CREDENTIAL_TYPE)
    @IssueCredentials({ MEMBERSHIP_CREDENTIAL_TYPE, SENSITIVE_DATA_CREDENTIAL_TYPE })
    public void cs_05_04_01_02_invalidScopeEscalationRequest(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var message = DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE)) // request more credentials than the token allows
                .build();

        var request = createPresentationRequest(authToken, message);
        executeRequest(request, TestFixtures::assert4XXXCode);
    }

}


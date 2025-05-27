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
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.IssuerService;
import org.eclipse.dataspacetck.dcp.system.annotation.RoleType;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveIssuerServiceEndpoint;

@IssuerService
@ExtendWith(SystemBootstrapExtension.class)
public abstract class AbstractCredentialIssuanceTest {

    protected final ObjectMapper mapper = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    @Inject
    @Did(HOLDER)
    protected String holderDid;
    @Inject
    @Holder
    protected KeyService holderKeyService;
    @Inject
    @Did(RoleType.ISSUER)
    protected String issuerDid;

    protected DcpMessageBuilder createCredentialRequestMessage(String holderPid) {
        return DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_REQUEST_MESSAGE_TYPE)
                .property("holderPid", holderPid)
                .property("credentials", List.of(
                        Map.of(
                                "id", "credential-object-id1"
                        ),
                        Map.of(
                                "id", "credential-object-id2"
                        )
                ));
    }

    /**
     * constructs a HTTP request using a CredentialRequestMessage
     */
    protected Request.Builder createCredentialRequest(String authToken, Map<String, Object> credentialRequestMessage) {
        var endpoint = resolveIssuerServiceEndpoint(issuerDid);
        try {
            var builder = new Request.Builder()
                    .url(endpoint + CREDENTIAL_REQUEST_PATH)
                    .post(RequestBody.create(mapper.writeValueAsString(credentialRequestMessage), MediaType.parse("application/json")));
            if (authToken != null) {
                builder.addHeader(AUTHORIZATION, "Bearer " + authToken);
            }
            return builder;
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    protected JWTClaimsSet.Builder createClaims() {
        return new JWTClaimsSet.Builder()
                .audience(issuerDid)
                .issuer(holderDid)
                .subject(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)));
    }

    protected String createToken(JWTClaimsSet claims) {
        return holderKeyService.sign(emptyMap(), claims);
    }

}

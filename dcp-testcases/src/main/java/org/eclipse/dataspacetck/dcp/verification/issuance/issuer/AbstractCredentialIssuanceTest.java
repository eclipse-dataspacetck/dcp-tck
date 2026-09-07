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

import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.IssuerService;
import org.eclipse.dataspacetck.dcp.system.annotation.RoleType;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialObject;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.extension.ExtendWith;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_METADATA_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveIssuerServiceEndpoint;

@IssuerService
@ExtendWith(SystemBootstrapExtension.class)
public abstract class AbstractCredentialIssuanceTest {

    protected final ObjectMapper mapper = JsonMapper.builder().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
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
        var endpoint = resolveIssuerServiceEndpoint(issuerDid);

        var builder = new Request.Builder()
                .header("Authorization", "Bearer " + createToken(createClaims().build()))
                .url(endpoint + ISSUER_METADATA_PATH)
                .get();

        try (var response = new OkHttpClient().newCall(builder.build()).execute()) {
            if (response.isSuccessful()) {
                var stream = response.body().string();
                var issuerMetadata = mapper.readValue(stream, IssuerMetadataMessage.class);

                var ids = issuerMetadata.getCredentialsSupported().stream()
                        .filter(co -> co.getProfile().equals("vc11-sl2021/jwt"))
                        .map(CredentialObject::getId)
                        .map(id -> Map.of("id", id))
                        .toList();
                return DcpMessageBuilder.newInstance()
                        .type(CREDENTIAL_REQUEST_MESSAGE_TYPE)
                        .property("holderPid", holderPid)
                        .property("credentials", ids);
            }
            throw new AssertionError("Expected IssuerMetadata to return 200 OK, but got " + response.code());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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
        } catch (JacksonException e) {
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

    /**
     * Signs a token with the holder's key but under a key id that resolves to no verification method.
     */
    protected String createTokenWithUnknownKid(JWTClaimsSet claims) {
        return holderKeyService.sign(Map.of("kid", holderDid + "#unresolvable-" + randomUUID()), claims);
    }

    /**
     * Signs a token whose iss/sub is a DID that cannot be resolved, so the receiver cannot obtain a key at all.
     */
    protected String createTokenWithUnresolvableSubject(JWTClaimsSet.Builder claims) {
        var unresolvable = TestFixtures.unresolvableDid(holderDid);
        var built = claims.issuer(unresolvable).subject(unresolvable).build();
        return holderKeyService.sign(Map.of("kid", unresolvable + "#" + holderKeyService.getPublicKey().getKeyID()), built);
    }

    private static class IssuerMetadataMessage {
        private String type;
        private String issuer;
        private Collection<CredentialObject> credentialsSupported;

        public String getType() {
            return type;
        }

        public String getIssuer() {
            return issuer;
        }

        public Collection<CredentialObject> getCredentialsSupported() {
            return credentialsSupported;
        }
    }
}

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

package org.eclipse.dataspacetck.dcp.system.cs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyServiceImpl;
import org.eclipse.dataspacetck.dcp.system.crypto.Keys;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.generation.JwtPresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.time.Instant.now;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.eclipse.dataspacetck.dcp.system.cs.CredentialServiceImpl.DEFAULT_SCOPE_PATTERN;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat.VC1_0_JWT;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialServiceImplTest {
    private static final String ISSUER_DID = "did:web:localhost%3A8083:issuer";
    private static final String HOLDER_DID = "did:web:localhost%3A8083:holder";
    private static final String VERIFIER_DID = "did:web:localhost%3A8083:verifier";
    private static final String CUSTOM_SCOPE = "my.scope:" + MEMBERSHIP_CREDENTIAL_TYPE + ":read";
    private static final Pattern CUSTOM_SCOPE_PATTERN = Pattern.compile("my.scope:(?<type>.*):(.*)");

    private final SecureTokenServer secureTokenServer = mock();
    private final TokenValidationService tokenService = mock();
    private final ObjectMapper mapper = new ObjectMapper();
    private JwtCredentialGenerator credentialGenerator;
    private JwtPresentationGenerator presentationGenerator;

    @BeforeEach
    void setUp() {
        var keyService = new KeyServiceImpl(Keys.generateEcKey());
        credentialGenerator = new JwtCredentialGenerator(ISSUER_DID, keyService);
        presentationGenerator = new JwtPresentationGenerator(HOLDER_DID, keyService);

        when(tokenService.validateToken(any())).thenReturn(Result.success(null));
        // the embedded STS resolves the scope to the bare credential type
        when(secureTokenServer.validateReadToken(any(), any())).thenReturn(Result.success(List.of(MEMBERSHIP_CREDENTIAL_TYPE)));
        when(secureTokenServer.validateWrite(any(), any())).thenReturn(Result.success());
    }

    @Test
    void presentationQuery_whenDefaultScopePattern() throws ParseException {
        var service = createService(DEFAULT_SCOPE_PATTERN);
        seedMembershipCredential(service);

        var result = service.presentationQueryMessage(VERIFIER_DID, "token", Map.of(SCOPE, List.of(MEMBERSHIP_SCOPE)));

        assertThat(result.succeeded()).isTrue();
        assertThat(presentedCredentials(result)).hasSize(1);
    }

    @Test
    void presentationQuery_whenCustomScopePattern() throws ParseException {
        var service = createService(CUSTOM_SCOPE_PATTERN);
        seedMembershipCredential(service);

        var result = service.presentationQueryMessage(VERIFIER_DID, "token", Map.of(SCOPE, List.of(CUSTOM_SCOPE)));

        assertThat(result.succeeded()).isTrue();
        assertThat(presentedCredentials(result)).hasSize(1);
    }

    /**
     * The embedded STS bakes the credential types into the read token, which {@code processScopeQuery} then
     * cross-checks against the types it extracts itself, so both must agree on the configured pattern.
     */
    @Test
    void presentationQuery_whenCustomScopePattern_againstEmbeddedSts() throws ParseException {
        var sts = new SecureTokenServerImpl(mock(), CUSTOM_SCOPE_PATTERN);
        var service = new CredentialServiceImpl(HOLDER_DID, List.of(presentationGenerator), sts, tokenService, mapper, CUSTOM_SCOPE_PATTERN);
        seedMembershipCredential(service);

        var token = sts.obtainReadToken(VERIFIER_DID, List.of(CUSTOM_SCOPE));
        var result = service.presentationQueryMessage(VERIFIER_DID, token.getContent(), Map.of(SCOPE, List.of(CUSTOM_SCOPE)));

        assertThat(result.succeeded()).isTrue();
        assertThat(presentedCredentials(result)).hasSize(1);
    }

    @Test
    void presentationQuery_whenScopeDoesNotMatchPattern() {
        var service = createService(CUSTOM_SCOPE_PATTERN);
        seedMembershipCredential(service);

        var result = service.presentationQueryMessage(VERIFIER_DID, "token", Map.of(SCOPE, List.of(MEMBERSHIP_SCOPE)));

        assertThat(result.failed()).isTrue();
        assertThat(result.getFailure()).isEqualTo("Invalid scope type: " + MEMBERSHIP_SCOPE);
    }

    @Test
    void createService_whenPatternHasNoTypeGroup() {
        assertThatThrownBy(() -> createService(Pattern.compile("my.scope:(.*):(.*)")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must declare a named group 'type'");
    }

    private CredentialServiceImpl createService(Pattern scopePattern) {
        return new CredentialServiceImpl(HOLDER_DID, List.of(presentationGenerator), secureTokenServer, tokenService, mapper, scopePattern);
    }

    private void seedMembershipCredential(CredentialServiceImpl service) {
        var credential = VerifiableCredential.Builder.newInstance()
                .id(randomUUID().toString())
                .issuanceDate(now().toString())
                .expirationDate(now().plusSeconds(600).toString())
                .issuer(ISSUER_DID)
                .type(List.of("VerifiableCredential", MEMBERSHIP_CREDENTIAL_TYPE))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .credentialSubject(Map.of("id", HOLDER_DID, "memberLevel", "gold"))
                .build();

        var message = Map.of(
                "issuerPid", randomUUID().toString(),
                "holderPid", randomUUID().toString(),
                "status", "ISSUED",
                "credentials", List.of(Map.of(
                        "credentialType", MEMBERSHIP_CREDENTIAL_TYPE,
                        "format", VC1_0_JWT.profileString,
                        "payload", credentialGenerator.generateCredential(credential).getContent()
                )));

        assertThat(service.writeCredentials("token", message).succeeded()).isTrue();
    }

    @SuppressWarnings("unchecked")
    private List<Object> presentedCredentials(Result<Map<String, Object>> result) throws ParseException {
        var presentations = (List<String>) result.getContent().get(PRESENTATION);
        assertThat(presentations).hasSize(1);
        var claims = SignedJWT.parse(presentations.get(0)).getJWTClaimsSet().getClaims();
        var vp = (Map<String, Object>) claims.get("vp");
        return (List<Object>) vp.get("verifiableCredential");
    }
}

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

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE_ALIAS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SecureTokenServerImplTest {
    private static final String DID = "did:web:test";
    private static final String CREDENTIAL_1 = "Credential1";
    private static final String SCOPE_1 = SCOPE_TYPE_ALIAS + CREDENTIAL_1;
    private static final String CREDENTIAL_2 = "Credential2";
    private static final String SCOPE_2 = SCOPE_TYPE_ALIAS + CREDENTIAL_2;
    private static final String AUDIENCE = "did:web:audience";
    private final TokenValidationService holderTokenService = mock();
    private final KeyService issuerKeyService = mock();
    private final SecureTokenServerImpl server = new SecureTokenServerImpl(mock());

    @Test
    void obtainReadToken() {
        var token = server.obtainReadToken(DID, List.of(SCOPE_1, SCOPE_2));

        var result = server.validateReadToken(DID, token.getContent());
        assertThat(result.succeeded()).isTrue();
        assertThat(result.getContent()).containsOnly(CREDENTIAL_1, CREDENTIAL_2);

        // validate single use
        assertThat(server.validateReadToken(DID, token.getContent()).succeeded()).isFalse();
    }

    @Test
    void readTokenIsInvalid() {
        var result = server.validateReadToken(DID, "invalid");
        assertThat(result.failed()).isTrue();
    }

    @Test
    void validateWrite() {
        when(holderTokenService.validateToken(anyString())).thenReturn(Result.success(null));
        var result = server.validateWrite("id", holderTokenService);
        assertThat(result.succeeded()).isTrue();
    }

    @Test
    void validateWrite_whenTokenInvalid() {
        when(holderTokenService.validateToken(anyString())).thenReturn(Result.failure("token invalid"));

        assertThat(server.validateWrite("id", holderTokenService).failed()).isTrue();
    }

    @Test
    void authorizeWrite() {
        when(issuerKeyService.sign(anyMap(), any(JWTClaimsSet.class)))
                .thenReturn("test-token");
        var result = server.authorizeWrite(issuerKeyService, DID, "id", AUDIENCE);
        assertThat(result).isEqualTo("test-token");
        verify(issuerKeyService).sign(anyMap(), argThat(claims -> {
            assertThat(claims.getAudience()).containsExactly(AUDIENCE);
            assertThat(claims.getIssuer()).isEqualTo(DID);
            assertThat(claims.getSubject()).isEqualTo(DID);
            assertThat(claims.getJWTID()).isEqualTo("id");
            return true;
        }));
    }

    @Test
    void authorizeWrite_whenSigningFails() {
        when(issuerKeyService.sign(anyMap(), any(JWTClaimsSet.class)))
                .thenThrow(new RuntimeException("Signing failed"));

        assertThatThrownBy(() -> server.authorizeWrite(issuerKeyService, DID, "id", AUDIENCE))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Signing failed");
    }
}
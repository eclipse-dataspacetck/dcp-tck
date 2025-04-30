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

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE_ALIAS;
import static org.mockito.Mockito.mock;

class SecureTokenServerImplTest {
    private static final String DID = "did:web:test";
    private static final String CREDENTIAL_1 = "Credential1";
    private static final String SCOPE_1 = SCOPE_TYPE_ALIAS + CREDENTIAL_1;
    private static final String CREDENTIAL_2 = "Credential2";
    private static final String SCOPE_2 = SCOPE_TYPE_ALIAS + CREDENTIAL_2;

    private final SecureTokenServerImpl server = new SecureTokenServerImpl(mock());

    @Test
    void verify_obtainReadToken() {
        var token = server.obtainReadToken(DID, List.of(SCOPE_1, SCOPE_2));

        var result = server.validateReadToken(DID, token.getContent());
        assertThat(result.succeeded()).isTrue();
        assertThat(result.getContent()).containsOnly(CREDENTIAL_1, CREDENTIAL_2);

        // validate single use
        assertThat(server.validateReadToken(DID, token.getContent()).succeeded()).isFalse();
    }

    @Test
    void verify_readTokenIsInvalid() {
        var result = server.validateReadToken(DID, "invalid");
        assertThat(result.failed()).isTrue();
    }

    @Test
    void verify_validateWrite() {
        server.authorizeWrite(DID, "id", List.of(SCOPE_1, SCOPE_2));
        var result = server.validateWrite(DID, "id");
        assertThat(result.succeeded()).isTrue();
        assertThat(result.getContent()).containsOnly(CREDENTIAL_1, CREDENTIAL_2);
    }

    @Test
    void verify_validateWriteExpired() {
        server.authorizeWrite(DID, "id", List.of(SCOPE_1));
        assertThat(server.validateWrite(DID, "id").succeeded()).isTrue();

        // validate single use
        assertThat(server.validateWrite(DID, "id").failed()).isTrue();
    }

    @Test
    void verify_writeTokenIsInvalid() {
        var result = server.validateWrite(DID, "id");
        assertThat(result.failed()).isTrue();
    }

    @Test
    void verify_writeTokenBearerIsInvalid() {
        server.authorizeWrite(DID, "id", List.of(SCOPE_1));
        var result = server.validateWrite("did:web:invalid:com", "id");
        assertThat(result.failed()).isTrue();
    }

    @Test
    void verify_writeIdIsInvalid() {
        server.authorizeWrite(DID, "id", List.of(SCOPE_1));
        var result = server.validateWrite(DID, "invalid");
        assertThat(result.failed()).isTrue();
    }
}
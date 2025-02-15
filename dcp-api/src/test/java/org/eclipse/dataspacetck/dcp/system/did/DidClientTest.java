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

package org.eclipse.dataspacetck.dcp.system.did;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class DidClientTest {

    @Test
    void verifyValidDids() {
        var client = new DidClient(true);
        assertThat(client.didToUrl("did:web:test.com")).isEqualTo("https://test.com/.well-known/did.json");
    }

    @MethodSource("validDids")
    @ParameterizedTest(name = "{index} {0}")
    void verifyDidToUrl(@SuppressWarnings("unused") String name, boolean https, String did, String expectedUrl) {
        var client = new DidClient(https);
        var url = client.didToUrl(did);
        assertThat(url).isEqualTo(expectedUrl);
    }

    @ParameterizedTest(name = "{index} {0}")
    @MethodSource("invalidDids")
    void verifyIllegalArgumentExceptionThrownIsMissingDidScheme(@SuppressWarnings("unused") String name, String did) {
        var client = new DidClient(true);
        assertThatIllegalArgumentException().isThrownBy(() -> client.didToUrl(did));
    }

    private static Stream<Arguments> validDids() {
        return Stream.of(
                Arguments.of("HTTP", false, "did:web:test.com", "http://test.com/.well-known/did.json"),
                Arguments.of("HTTPS", true, "did:web:test.com", "https://test.com/.well-known/did.json"),
                Arguments.of("HTTPS with path", true, "did:web:test.com:holder", "https://test.com/holder/did.json"),
                Arguments.of("HTTPS with domain and port", true, "did:web:example.com%3A3000:verifier", "https://example.com:3000/verifier/did.json")
        );
    }

    private static Stream<Arguments> invalidDids() {
        return Stream.of(
                Arguments.of("Invalid scheme", "did:foo:test.com"),
                Arguments.of("Missing DID method", "did:test.com:holder"),
                Arguments.of("Missing scheme", "test.com:holder")
        );
    }
}
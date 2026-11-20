/*
 *  Copyright (c) 2026 Metaform Systems, Inc.
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

package org.eclipse.dataspacetck.dcp.system.revocation;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BitstringStatusListServiceTest {
    // both status list specifications require the uncompressed bitstring to be at least 16KB
    private static final int MINIMUM_ENTRIES = 131_072;

    private final BitstringStatusListService service = new BitstringStatusListService("did:web:localhost%3A8083:issuer", "http://localhost:8083");

    @Test
    void createStatusListCredential_hasMinimumSize() throws IOException {
        assertThat(decode(encodedList())).hasSize(MINIMUM_ENTRIES / 8);
    }

    @Test
    void createStatusListCredential_hasMultibasePrefix() {
        // "u" denotes base64url without padding; a GZIP stream always starts with the bytes 1f 8b 08, i.e. "H4sI"
        assertThat(encodedList()).startsWith("uH4sI");
    }

    @Test
    void createStatusListCredential_containsRevokedEntry() throws IOException {
        service.setRevoked(1);

        // entries are indexed from the left-most bit
        assertThat(decode(encodedList())[0]).isEqualTo((byte) 0b0100_0000);
        assertThat(service.isRevoked(1)).isTrue();
        assertThat(service.isRevoked(0)).isFalse();
    }

    @Test
    void setRevoked_acceptsLastEntry() {
        service.setRevoked(MINIMUM_ENTRIES - 1);

        assertThat(service.isRevoked(MINIMUM_ENTRIES - 1)).isTrue();
    }

    @Test
    void setRevoked_whenIndexOutOfRange() {
        assertThatThrownBy(() -> service.setRevoked(MINIMUM_ENTRIES)).isInstanceOf(IndexOutOfBoundsException.class);
    }

    @Test
    void getStatusEntryType() {
        assertThat(service.getStatusEntryType()).isEqualTo("BitstringStatusListEntry");
    }

    @SuppressWarnings("unchecked")
    private String encodedList() {
        var subject = (Map<String, Object>) service.createStatusListCredential().toMap().get("credentialSubject");
        return (String) subject.get("encodedList");
    }

    private byte[] decode(String encodedList) throws IOException {
        var compressed = Base64.getUrlDecoder().decode(encodedList.substring(1));
        try (var stream = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            return stream.readAllBytes();
        }
    }
}

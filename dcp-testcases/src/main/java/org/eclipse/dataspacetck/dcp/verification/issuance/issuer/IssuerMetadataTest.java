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

import okhttp3.Request;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialObject;
import org.junit.jupiter.api.DisplayName;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_METADATA_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.assert2xxCode;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.bodyAs;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequestAndGet;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.resolveIssuerServiceEndpoint;

public class IssuerMetadataTest extends AbstractCredentialIssuanceTest {


    @MandatoryTest
    @DisplayName("6.7 Verify correct Issuer Metadata")
    void is_6_7_issuerMetadata() {
        var endpoint = resolveIssuerServiceEndpoint(issuerDid);
        var request = new Request.Builder()
                              .url(endpoint + ISSUER_METADATA_PATH)
                              .get()
                              .build();

        executeRequest(request, r -> {
            assert2xxCode(r);
            var metadata = bodyAs(r, IssuerMetadata.class, mapper);
            assertThat(metadata).isNotNull();
            assertThat(metadata.type()).isEqualTo("IssuerMetadata");
            assertThat(metadata.issuer()).isEqualTo(issuerDid);
            assertThat(metadata.credentialsSupported()).isNotEmpty();
        });
    }

    @MandatoryTest
    @DisplayName("6.7.1 Verify each CredentialObject is fully populated")
    void is_6_7_1_issuerMetadata_credentialObjectProperties() {
        var metadata = fetchMetadata();

        assertThat(metadata.credentialsSupported()).allSatisfy(credentialObject -> {
            assertThat(credentialObject.getId()).isNotBlank();
            assertThat(credentialObject.getType()).isEqualTo("CredentialObject");
            assertThat(credentialObject.getCredentialType()).isNotBlank();
            assertThat(credentialObject.getProfile())
                    .withFailMessage("CredentialObject '%s' must declare a profile", credentialObject.getId())
                    .isNotBlank();
            assertThat(credentialObject.getBindingMethods())
                    .withFailMessage("CredentialObject '%s' must declare at least one binding method",
                            credentialObject.getId())
                    .isNotEmpty();
        });
    }

    @MandatoryTest
    @DisplayName("6.7 Verify CredentialObject ids are stable across metadata requests")
    void is_6_7_issuerMetadata_stableIds() {
        var first = credentialObjectIds(fetchMetadata());
        var second = credentialObjectIds(fetchMetadata());

        assertThat(second)
                .withFailMessage("CredentialObject ids must be stable so that offers and requests can reference them")
                .containsExactlyInAnyOrderElementsOf(first);
    }

    private List<String> credentialObjectIds(IssuerMetadata metadata) {
        return metadata.credentialsSupported().stream().map(CredentialObject::getId).sorted().toList();
    }

    private IssuerMetadata fetchMetadata() {
        var request = new Request.Builder()
                .url(resolveIssuerServiceEndpoint(issuerDid) + ISSUER_METADATA_PATH)
                .get()
                .build();

        return executeRequestAndGet(request, r -> {
            assert2xxCode(r);
            return bodyAs(r, IssuerMetadata.class, mapper);
        });
    }

    private record IssuerMetadata(String type, String issuer,
                                  Collection<CredentialObject> credentialsSupported) {
    }
}

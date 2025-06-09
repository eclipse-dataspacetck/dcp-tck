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

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_METADATA_PATH;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.assert2xxCode;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.bodyAs;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;
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

    private record IssuerMetadata(String type, String issuer,
                                  Collection<CredentialObject> credentialsSupported) {
    }
}

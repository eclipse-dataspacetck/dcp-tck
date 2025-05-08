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

import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_SERVICE_TYPE;

public class EndpointDiscoveryTest extends AbstractCredentialIssuanceTest {


    @MandatoryTest
    @DisplayName("6.2 Endpoint Discovery")
    void is_6_2_endpointDiscovery() {
        var client = new DidClient(false);
        var doc = client.resolveDocument(issuerDid);

        assertThat(doc).isNotNull();
        assertThat(doc.getServiceEntry(ISSUER_SERVICE_TYPE)).isNotNull();
    }

}

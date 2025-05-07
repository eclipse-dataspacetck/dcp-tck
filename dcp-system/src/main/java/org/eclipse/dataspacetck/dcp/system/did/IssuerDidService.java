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

package org.eclipse.dataspacetck.dcp.system.did;

import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.model.did.DidDocument;
import org.eclipse.dataspacetck.dcp.system.model.did.ServiceEntry;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.List;

import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * DID Service implementation specifically for Issuer services. In addition to the {@code CredentialService} endpoint, it
 * also contains an {@code IssuerService} endpoint.
 */
public class IssuerDidService extends DidServiceImpl {

    public IssuerDidService(String did, String baseEndpoint, KeyService keyService) {
        super(did, baseEndpoint, keyService);
    }

    @Override
    public Result<DidDocument> resolveDidDocument() {
        var document = createDocumentBuilder()
                .service(List.of(new ServiceEntry("TCK-Issuer-Service", "IssuerService", baseEndpoint)))
                .build();
        return success(document);
    }
}

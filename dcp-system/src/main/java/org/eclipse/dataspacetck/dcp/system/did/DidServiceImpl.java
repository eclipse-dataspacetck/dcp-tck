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

import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.model.did.DidDocument;
import org.eclipse.dataspacetck.dcp.system.model.did.ServiceEntry;
import org.eclipse.dataspacetck.dcp.system.model.did.VerificationMethod;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.List;

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.DCP_NAMESPACE;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * Default implementation.
 */
public class DidServiceImpl implements DidService {
    private static final String DID_CONTEXT = "https://www.w3.org/ns/did/v1";

    private final String did;
    private final String baseEndpoint;
    private final KeyService keyService;

    public DidServiceImpl(String did, String baseEndpoint, KeyService keyService) {
        this.did = did;
        this.baseEndpoint = baseEndpoint;
        this.keyService = keyService;
    }

    @Override
    public Result<DidDocument> resolveDidDocument() {
        var document = DidDocument.Builder.newInstance()
                .id(did)
                .context(List.of(DID_CONTEXT, DCP_NAMESPACE))
                .service(List.of(new ServiceEntry("TCK-Credential-Service", CREDENTIAL_SERVICE_TYPE, baseEndpoint)))
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id(did + "#" + keyService.getPublicKey().getKeyID())
                        .type("JsonWebKey2020") // FIXME
                        .controller(did)
                        .publicKeyJwk(keyService.getPublicKey().toJSONObject())
                        .build()))
                .build();
        return success(document);
    }

}

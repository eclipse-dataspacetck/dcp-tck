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

    protected final String did;
    protected final String baseEndpoint;
    protected final KeyService keyService;
    private final List<KeyService> keyServices;
    private final boolean includeCapabilityInvocation;

    public DidServiceImpl(String did, String baseEndpoint, KeyService keyService) {
        this(did, baseEndpoint, List.of(keyService), true);
    }

    public DidServiceImpl(String did, String baseEndpoint, List<KeyService> keyServices, boolean includeCapabilityInvocation) {
        this.did = did;
        this.baseEndpoint = baseEndpoint;
        this.keyService = keyServices.get(0);
        this.keyServices = keyServices;
        this.includeCapabilityInvocation = includeCapabilityInvocation;
    }

    @Override
    public Result<DidDocument> resolveDidDocument() {
        var document = createDocumentBuilder().build();
        return success(document);
    }

    protected DidDocument.Builder createDocumentBuilder() {
        var vms = keyServices.stream()
                .map(ks -> VerificationMethod.Builder.newInstance()
                        .id(did + "#" + ks.getPublicKey().getKeyID())
                        .type("JsonWebKey2020") // FIXME
                        .controller(did)
                        .publicKeyJwk(ks.getPublicKey().toJSONObject())
                        .build())
                .toList();
        var vmIds = vms.stream().map(VerificationMethod::getId).toList();
        var builder = DidDocument.Builder.newInstance()
                .id(did)
                .context(List.of(DID_CONTEXT, DCP_NAMESPACE))
                .service(List.of(new ServiceEntry("TCK-Credential-Service", CREDENTIAL_SERVICE_TYPE, baseEndpoint)))
                .verificationMethod(vms)
                .authentication(vmIds)
                .assertionMethod(vmIds);
        if (includeCapabilityInvocation) {
            builder.capabilityInvocation(vmIds);
        }
        return builder;
    }

}

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

package org.eclipse.dataspacetck.dcp.system.assembly;

import org.eclipse.dataspacetck.core.api.system.CallbackEndpoint;
import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;
import org.eclipse.dataspacetck.core.spi.system.ServiceResolver;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialServiceImpl;
import org.eclipse.dataspacetck.dcp.system.cs.PresentationHandler;
import org.eclipse.dataspacetck.dcp.system.did.DidDocumentHandler;
import org.eclipse.dataspacetck.dcp.system.did.DidService;

import static java.util.Objects.requireNonNull;

/**
 * Assembles services that must reinitialized per test invocation.
 */
public class ServiceAssembly {
    private CredentialService credentialService;
    private DidService didService;

    public ServiceAssembly(BaseAssembly baseAssembly, ServiceResolver resolver, ServiceConfiguration configuration) {
        credentialService = new CredentialServiceImpl(baseAssembly.getAddress(),
                baseAssembly.getVerifierTokenService(),
                baseAssembly.getVerifierDid(),
                baseAssembly.getVerifierKeyService());

        var endpoint = (CallbackEndpoint) requireNonNull(resolver.resolve(CallbackEndpoint.class, configuration));
        var monitor = configuration.getMonitor();
        var mapper = baseAssembly.getMapper();

        // register the handlers
        var presentationHandler = new PresentationHandler(credentialService, mapper, monitor);
        endpoint.registerProtocolHandler("/presentations/query", presentationHandler);

        endpoint.registerHandler("/holder/did.json", new DidDocumentHandler(baseAssembly.getHolderDidService(), mapper));
        endpoint.registerHandler("/verifier/did.json", new DidDocumentHandler(baseAssembly.getVerifierDidService(), mapper));
    }

    public CredentialService getCredentialService() {
        return credentialService;
    }

    public DidService getDidService() {
        return didService;
    }
}

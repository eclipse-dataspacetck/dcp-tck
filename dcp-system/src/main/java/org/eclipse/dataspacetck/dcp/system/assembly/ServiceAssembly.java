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
import org.eclipse.dataspacetck.dcp.system.cs.SecureTokenServerImpl;
import org.eclipse.dataspacetck.dcp.system.did.DidDocumentHandler;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.generation.JwtPresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.eclipse.dataspacetck.dcp.system.sts.StsClient;
import org.jetbrains.annotations.NotNull;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat.VC1_0_JWT;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_SCOPE;

/**
 * Assembles services that must reinitialized per test invocation.
 */
public class ServiceAssembly {
    private CredentialService credentialService;
    private SecureTokenServerImpl secureTokenServer;

    public ServiceAssembly(BaseAssembly baseAssembly, ServiceResolver resolver, ServiceConfiguration configuration) {
        var generator = new JwtPresentationGenerator(baseAssembly.getHolderDid(), baseAssembly.getHolderKeyService());
        secureTokenServer = new SecureTokenServerImpl();
        credentialService = new CredentialServiceImpl(baseAssembly.getHolderDid(), List.of(generator), secureTokenServer);

        // FIXME: Seed test credentials until issuance is implemented
        seedCredentials(baseAssembly, secureTokenServer);

        var endpoint = (CallbackEndpoint) requireNonNull(resolver.resolve(CallbackEndpoint.class, configuration));
        var monitor = configuration.getMonitor();
        var mapper = baseAssembly.getMapper();

        // register the handlers
        var tokenService = baseAssembly.getHolderTokenService();
        var presentationHandler = new PresentationHandler(credentialService, tokenService, mapper, monitor);
        endpoint.registerProtocolHandler("/presentations/query", presentationHandler);

        endpoint.registerHandler("/holder/did.json", new DidDocumentHandler(baseAssembly.getHolderDidService(), mapper));
        endpoint.registerHandler("/verifier/did.json", new DidDocumentHandler(baseAssembly.getVerifierDidService(), mapper));
        endpoint.registerHandler("/issuer/did.json", new DidDocumentHandler(baseAssembly.getIssuerDidService(), mapper));
    }

    public CredentialService getCredentialService() {
        return credentialService;
    }

    public StsClient getStsClient() {
        return secureTokenServer;
    }

    private void seedCredentials(BaseAssembly baseAssembly, SecureTokenServer secureTokenServer) {
        var issuerDid = baseAssembly.getIssuerDid();
        var credentialGenerator = new JwtCredentialGenerator(issuerDid, baseAssembly.getIssuerKeyService());

        var holderDid = baseAssembly.getHolderDid();

        var membershipContainer = createVcContainer(issuerDid, holderDid, credentialGenerator, MEMBERSHIP_CREDENTIAL_TYPE);
        var sensitiveDataContainer = createVcContainer(issuerDid, holderDid, credentialGenerator, SENSITIVE_DATA_CREDENTIAL_TYPE);

        var correlation = randomUUID().toString();
        secureTokenServer.authorizeWrite(issuerDid, correlation, List.of(MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE));
        credentialService.writeCredentials(issuerDid, correlation, List.of(membershipContainer, sensitiveDataContainer));
    }

    @NotNull
    private VcContainer createVcContainer(String issuerDid, String holderDid,
                                          JwtCredentialGenerator credentialGenerator,
                                          String credentialType) {
        var credential = createCredential(issuerDid, holderDid,credentialType);
        var result = credentialGenerator.generateCredential(credential);
        return new VcContainer(result.getContent(), credential, VC1_0_JWT);
    }

    private VerifiableCredential createCredential(String issuerDid, String holderDid, String credentialType) {
        return VerifiableCredential.Builder.newInstance()
                .credentialSubject(Map.of("id", holderDid))
                .id(randomUUID().toString())
                .issuanceDate(new Date().toString())
                .issuer(issuerDid)
                .type(List.of(credentialType))
                .build();

    }

}

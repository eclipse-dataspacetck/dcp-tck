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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.core.api.system.CallbackEndpoint;
import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;
import org.eclipse.dataspacetck.core.spi.system.ServiceResolver;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialServiceImpl;
import org.eclipse.dataspacetck.dcp.system.cs.PresentationHandler;
import org.eclipse.dataspacetck.dcp.system.cs.SecureTokenServerImpl;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.did.DidDocumentHandler;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.generation.JwtPresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.eclipse.dataspacetck.dcp.system.sts.StsClient;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.time.Instant.now;
import static java.util.Objects.requireNonNull;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_OFFER_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat.VC1_0_JWT;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_CREDENTIAL_TYPE;

/**
 * Assembles services that must reinitialized per test invocation.
 */
public class ServiceAssembly {
    private final CredentialService credentialService;
    private final SecureTokenServer secureTokenServer;

    public ServiceAssembly(BaseAssembly baseAssembly, ServiceResolver resolver, ServiceConfiguration configuration) {
        var generator = new JwtPresentationGenerator(baseAssembly.getHolderDid(), baseAssembly.getHolderKeyService());
        secureTokenServer = new SecureTokenServerImpl(configuration);
        credentialService = new CredentialServiceImpl(baseAssembly.getHolderDid(), List.of(generator), secureTokenServer);

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
        endpoint.registerHandler("/thirdparty/did.json", new DidDocumentHandler(baseAssembly.getThirdPartyDidService(), mapper));

        // FIXME: Seed test credentials until issuance is implemented
        seedCredentials(baseAssembly);
    }

    public CredentialService getCredentialService() {
        return credentialService;
    }

    public StsClient getStsClient() {
        return secureTokenServer;
    }

    private void seedCredentials(BaseAssembly baseAssembly) {
        var issuerDid = baseAssembly.getIssuerDid();
        var credentialGenerator = new JwtCredentialGenerator(issuerDid, baseAssembly.getIssuerKeyService());

        var holderDid = baseAssembly.getHolderDid();

        var membershipContainer = createVcContainer(issuerDid, holderDid, credentialGenerator, MEMBERSHIP_CREDENTIAL_TYPE);
        var sensitiveDataContainer = createVcContainer(issuerDid, holderDid, credentialGenerator, SENSITIVE_DATA_CREDENTIAL_TYPE);

        var correlation = randomUUID().toString();

        // var token = secureTokenServer.authorizeWrite(issuerDid, correlation, List.of(MEMBERSHIP_SCOPE_WRITE, SENSITIVE_DATA_SCOPE_WRITE)).getContent();

        var claimSet = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .audience(holderDid)
                .subject(issuerDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .build();

        var token = baseAssembly.getIssuerKeyService().sign(Collections.emptyMap(), claimSet);

        try {
            sendCredentialMessage(baseAssembly, correlation, membershipContainer, sensitiveDataContainer, token);
            sendCredentialOfferMessage(baseAssembly, token);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

    }

    private void sendCredentialOfferMessage(BaseAssembly baseAssembly, String token) throws JsonProcessingException {
        var credentialsOfferObject = DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_OFFER_MESSAGE_TYPE)
                .property("https://w3id.org/dspace-dcp/v1.0/issuer", baseAssembly.getIssuerDid())
                .property("https://w3id.org/dspace-dcp/v1.0/credentials", List.of(
                        Map.of(
                                "https://w3id.org/dspace-dcp/v1.0/profile", "vc11-sl2021/jwt",
                                "https://w3id.org/dspace-dcp/v1.0/credentialType", MEMBERSHIP_CREDENTIAL_TYPE,
                                "https://w3id.org/dspace-dcp/v1.0/offerReason", "issuance",
                                "https://w3id.org/dspace-dcp/v1.0/bindingMethods", "did:web"
                        )
                ));
        var msg = baseAssembly.getMapper().writeValueAsString(credentialsOfferObject.build());
        sendDcpMessage(msg, "/offers", token, baseAssembly.getHolderDid());

    }

    private void sendCredentialMessage(BaseAssembly baseAssembly, String correlation, VcContainer membershipContainer, VcContainer sensitiveDataContainer, String token) throws JsonProcessingException {
        var credentialsObject = DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_MESSAGE_TYPE)
                .property("requestId", correlation)
                .property("issuerPid", UUID.randomUUID().toString())
                .property("holderPid", UUID.randomUUID().toString())
                .property("credentials", List.of(
                        Map.of(
                                "credentialType", MEMBERSHIP_CREDENTIAL_TYPE,
                                "format", "VC_1_0_JWT",
                                "payload", membershipContainer.rawCredential()
                        ),
                        Map.of(
                                "credentialType", SENSITIVE_DATA_CREDENTIAL_TYPE,
                                "format", "VC_1_0_JWT",
                                "payload", sensitiveDataContainer.rawCredential()
                        )));

        var msg = baseAssembly.getMapper().writeValueAsString(credentialsObject.build());
        sendDcpMessage(msg, "/credentials", token, baseAssembly.getHolderDid());
    }

    private void sendDcpMessage(String messageObject, String path, String token, String holderDid) {
        var dd = new DidClient(false).resolveDocument(holderDid);
        var service = dd.getServiceEntry(CREDENTIAL_SERVICE_TYPE);

        try {
            var rq = new Request.Builder()
                    .url(service.getServiceEndpoint() + path)
                    .post(RequestBody.create(messageObject, MediaType.parse("application/json")))
                    .addHeader("Authorization", "Bearer " + token)
                    .build();

            var client = new OkHttpClient();
            try (var response = client.newCall(rq).execute()) {
                if (!response.isSuccessful()) {
                    throw new RuntimeException("Failed to seed credentials: " + response.message());
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @NotNull
    private VcContainer createVcContainer(String issuerDid, String holderDid,
                                          JwtCredentialGenerator credentialGenerator,
                                          String credentialType) {
        var credential = createCredential(issuerDid, holderDid, credentialType);
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

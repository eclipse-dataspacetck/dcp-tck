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
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.core.api.system.CallbackEndpoint;
import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;
import org.eclipse.dataspacetck.core.spi.system.ServiceResolver;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialApiHandler;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialOfferHandler;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialServiceImpl;
import org.eclipse.dataspacetck.dcp.system.cs.PresentationHandler;
import org.eclipse.dataspacetck.dcp.system.cs.SecureTokenServerImpl;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.did.DidDocumentHandler;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.generation.JwtPresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.handler.SchemaProvider;
import org.eclipse.dataspacetck.dcp.system.issuer.CredentialRequestHandler;
import org.eclipse.dataspacetck.dcp.system.issuer.IssuerService;
import org.eclipse.dataspacetck.dcp.system.issuer.IssuerServiceImpl;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.revocation.BitstringStatusListService;
import org.eclipse.dataspacetck.dcp.system.revocation.CredentialRevocationHandler;
import org.eclipse.dataspacetck.dcp.system.revocation.CredentialRevocationService;
import org.eclipse.dataspacetck.dcp.system.revocation.StatusList2021Service;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.eclipse.dataspacetck.dcp.system.sts.StsClient;
import org.eclipse.dataspacetck.dcp.system.verifier.BaseTokenValidationService;
import org.eclipse.dataspacetck.dcp.system.verifier.VerifierTriggerHandler;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.time.Instant.now;
import static java.util.Objects.requireNonNull;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;
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
    private final IssuerService issuerService;
    private final CredentialRevocationService revocationService;
    public ServiceAssembly(BaseAssembly baseAssembly, ServiceResolver resolver, ServiceConfiguration configuration) {
        var tokenService = baseAssembly.getHolderTokenService();
        var generator = new JwtPresentationGenerator(baseAssembly.getHolderDid(), baseAssembly.getHolderKeyService());
        var mapper = baseAssembly.getMapper();

        secureTokenServer = new SecureTokenServerImpl(configuration);
        credentialService = new CredentialServiceImpl(baseAssembly.getHolderDid(), List.of(generator), secureTokenServer, baseAssembly.getHolderTokenService(), mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES));
        issuerService = new IssuerServiceImpl(baseAssembly.getIssuerKeyService(), baseAssembly.getIssuerTokenService());
        revocationService = createRevocationService(baseAssembly);

        var endpoint = (CallbackEndpoint) requireNonNull(resolver.resolve(CallbackEndpoint.class, configuration));
        var monitor = configuration.getMonitor();

        // register the handlers

        // ... for presentation query
        var presentationHandler = new PresentationHandler(credentialService, tokenService, mapper, monitor);
        endpoint.registerProtocolHandler("/presentations/query", presentationHandler);

        // ... for credential issuance
        endpoint.registerProtocolHandler("/credentials", new CredentialApiHandler(credentialService, mapper, issuerService));
        endpoint.registerProtocolHandler("/offers", new CredentialOfferHandler(credentialService));
        endpoint.registerProtocolHandler("/requests/.*", new CredentialRequestHandler(issuerService, mapper));

        endpoint.registerHandler("/holder/did.json", new DidDocumentHandler(baseAssembly.getHolderDidService(), mapper));
        endpoint.registerHandler("/verifier/did.json", new DidDocumentHandler(baseAssembly.getVerifierDidService(), mapper));
        endpoint.registerHandler("/issuer/did.json", new DidDocumentHandler(baseAssembly.getIssuerDidService(), mapper));
        endpoint.registerHandler("/thirdparty/did.json", new DidDocumentHandler(baseAssembly.getThirdPartyDidService(), mapper));

        // ... for the verifier's trigger endpoint
        endpoint.registerProtocolHandler("/api/trigger", new VerifierTriggerHandler(baseAssembly.getVerifierTokenService(),
                mapper,
                baseAssembly.getVerifierKeyService(),
                baseAssembly.getVerifierDid(),
                new BaseTokenValidationService(),
                revocationService));

        // ... for revocation
        endpoint.registerHandler("/statuslist/.*", new CredentialRevocationHandler(revocationService, mapper));
        // ... schema validation
        endpoint.registerProtocolHandler("/schema/.*", new SchemaProvider());
    }

    public CredentialService getCredentialService() {
        return credentialService;
    }

    public CredentialRevocationService getRevocationService() {
        return revocationService;
    }

    public StsClient getStsClient() {
        return secureTokenServer;
    }

    public void issueCredentials(BaseAssembly baseAssembly) {
        var issuerDid = baseAssembly.getIssuerDid();
        var credentialGenerator = new JwtCredentialGenerator(issuerDid, baseAssembly.getIssuerKeyService());

        var holderDid = baseAssembly.getHolderDid();

        var membershipContainer = createVcContainer(issuerDid, holderDid, credentialGenerator, MEMBERSHIP_CREDENTIAL_TYPE);
        var sensitiveDataContainer = createVcContainer(issuerDid, holderDid, credentialGenerator, SENSITIVE_DATA_CREDENTIAL_TYPE);

        var correlation = baseAssembly.getHolderPid();

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
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

    }

    @NotNull
    public VcContainer createVcContainer(String issuerDid, String holderDid,
                                         JwtCredentialGenerator credentialGenerator,
                                         String credentialType) {
        var credential = createCredential(issuerDid, holderDid, credentialType);
        var result = credentialGenerator.generateCredential(credential);
        return new VcContainer(result.getContent(), credential, VC1_0_JWT);
    }

    private CredentialRevocationService createRevocationService(BaseAssembly baseAssembly) {
        return switch (baseAssembly.getRevocationListType().toLowerCase()) {
            case "bitstringstatuslist" ->
                    new BitstringStatusListService(baseAssembly.getIssuerDid(), baseAssembly.getAddress());
            case "statuslist2021" -> new StatusList2021Service(baseAssembly.getIssuerDid(), baseAssembly.getAddress());
            default ->
                    throw new IllegalArgumentException("Unsupported revocation list type: " + baseAssembly.getRevocationListType());
        };
    }

    private void sendCredentialMessage(BaseAssembly baseAssembly, String correlation, VcContainer membershipContainer, VcContainer sensitiveDataContainer, String token) throws JsonProcessingException {
        var credentialsObject = DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_MESSAGE_TYPE)
                .property("requestId", correlation)
                .property("issuerPid", UUID.randomUUID().toString())
                .property("holderPid", correlation)
                .property("credentials", List.of(
                        Map.of(
                                "credentialType", MEMBERSHIP_CREDENTIAL_TYPE,
                                "format", "VC1_0_JWT",
                                "payload", membershipContainer.rawCredential()
                        ),
                        Map.of(
                                "credentialType", SENSITIVE_DATA_CREDENTIAL_TYPE,
                                "format", "VC1_0_JWT",
                                "payload", sensitiveDataContainer.rawCredential()
                        )))
                .property("status", "ISSUED");

        var msg = baseAssembly.getMapper().writeValueAsString(credentialsObject.build());
        sendCredentialServiceMessage(msg, "/credentials", token, baseAssembly.getHolderDid());
    }

    /**
     * Sends a message to the credential service.
     *
     * @param messageObject the message object to send, e.g. a CredentialMessage, a CredentialOfferMessage, etc.
     * @param path          the exact endpoint path to send the message to
     * @param token         the ID token to use for authentication
     * @param holderDid     the holder DID. Used to resolve the message recipient's CredentialService base URL.
     */
    private void sendCredentialServiceMessage(String messageObject, String path, String token, String holderDid) {
        var dd = new DidClient(false).resolveDocument(holderDid);
        var service = dd.getServiceEntry(CREDENTIAL_SERVICE_TYPE);

        try {
            var rq = new Request.Builder()
                    .url(service.serviceEndpoint() + path)
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

    private VerifiableCredential createCredential(String issuerDid, String holderDid, String credentialType) {
        return VerifiableCredential.Builder.newInstance()
                .id(randomUUID().toString())
                .issuanceDate(Instant.now().toString())
                .issuer(issuerDid)
                .type(List.of(credentialType))
                // credential subject cannot be empty
                .credentialSubject(Map.of("id", holderDid, "foo", "bar"))
                .build();

    }

}

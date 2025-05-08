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

package org.eclipse.dataspacetck.dcp.system.issuer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialMessage;
import org.eclipse.dataspacetck.dcp.system.cs.TokenValidationService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.io.IOException;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;

import static java.time.Instant.now;
import static java.util.UUID.randomUUID;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

public class IssuerServiceImpl implements IssuerService {
    private final KeyService issuerKeyService;
    private final TokenValidationService issuerTokenValidationService;
    private final ObjectMapper objectMapper;
    private final Map<String, RequestStatus> credentialRequests = new java.util.HashMap<>();

    public IssuerServiceImpl(KeyService issuerKeyService, TokenValidationService issuerTokenValidationService) {
        this.issuerKeyService = issuerKeyService;
        this.issuerTokenValidationService = issuerTokenValidationService;
        objectMapper = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    }

    private static Result<String> generateJwtCredential(CredentialRequestMessage.CredentialDescriptor cred, JwtCredentialGenerator gen, String holderDid, String issuerDid) {
        return gen.generateCredential(VerifiableCredential.Builder.newInstance()
                .credentialSubject(Map.of("id", holderDid))
                .id(randomUUID().toString())
                .issuanceDate(now().toString())
                .issuer(issuerDid)
                .type(List.of(cred.credentialType()))
                .credentialSubject(Map.of("id", holderDid, "bar", "baz"))
                .build());
    }

    @Override
    public Result<String> processCredentialRequest(String idTokenJwt, Map<String, Object> credentialRequestMessage) {

        // validate the token
        var validationResult = issuerTokenValidationService.validateToken(idTokenJwt);
        if (!validationResult.succeeded()) {
            return failure(validationResult.getFailure(), Result.ErrorType.UNAUTHORIZED);
        }

        // parse token claims
        var jwt = validationResult.getContent();
        String issuerDid;
        String holderDid;
        try {
            issuerDid = jwt.getJWTClaimsSet().getAudience().get(0);
            holderDid = jwt.getJWTClaimsSet().getIssuer();
        } catch (ParseException e) {
            return failure("Error parsing holder's token: " + e.getMessage(), Result.ErrorType.UNAUTHORIZED);
        }
        var gen = new JwtCredentialGenerator(issuerDid, issuerKeyService);

        // parse message
        var credentialRequest = objectMapper.convertValue(credentialRequestMessage, CredentialRequestMessage.class);
        if (!credentialRequest.validate()) {
            return failure("Invalid credential request message", Result.ErrorType.BAD_REQUEST);
        }


        // generate CredentialMessage
        var correlation = credentialRequest.getHolderPid();
        var credentials = credentialRequest.getCredentials().stream()
                .map(cred -> new CredentialMessage.CredentialContainer(cred.credentialType(),
                        generateJwtCredential(cred, gen, holderDid, issuerDid).getContent(), cred.format()
                )).toList();
        var issuerPid = randomUUID().toString();
        var credentialsMessage = CredentialMessage.Builder.newInstance()
                .holderPid(correlation)
                .issuerPid(issuerPid)
                .status("ISSUED")
                .credentials(credentials)
                .build();

        credentialRequests.put(issuerPid, new RequestStatus(credentialRequest, "RECEIVED"));

        // send CredentialMessage to holder's Storage API
        sendBackCredentials(holderDid, issuerDid, credentialsMessage);

        return success(issuerPid);
    }

    @Override
    public Result<Map<String, String>> getCredentialStatus(String idTokenJwt, String id) {
        // validate the token
        var validationResult = issuerTokenValidationService.validateToken(idTokenJwt);
        if (!validationResult.succeeded()) {
            return failure(validationResult.getFailure(), Result.ErrorType.UNAUTHORIZED);
        }
        return Optional.ofNullable(credentialRequests.get(id)).map(rqs -> success(Map.of(
                        "type", "CredentialStatus",
                        "holderPid", rqs.credentialRequest.getHolderPid(),
                        "issuerPid", id,
                        "status", rqs.status.toUpperCase()
                )))
                .orElseGet(() -> failure("No credential request found", Result.ErrorType.NOT_FOUND));
    }

    private void sendBackCredentials(String holderDid, String issuerDid, CredentialMessage credentialsMsg) {
        var scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        scheduledExecutorService
                .schedule(() -> {
                    var claims = new JWTClaimsSet.Builder()
                            .audience(holderDid)
                            .issuer(issuerDid)
                            .subject(issuerDid)
                            .jwtID(randomUUID().toString())
                            .issueTime(new Date())
                            .expirationTime(Date.from(now().plusSeconds(600)))
                            .build();

                    var token = issuerKeyService.sign(Collections.emptyMap(), claims);
                    var didClient = new DidClient(false);
                    var endpoint = didClient.resolveDocument(holderDid).getServiceEntry(CREDENTIAL_SERVICE_TYPE).serviceEndpoint();
                    String body;
                    try {
                        body = objectMapper.writeValueAsString(credentialsMsg);
                    } catch (JsonProcessingException e) {
                        throw new RuntimeException(e);
                    }
                    var rq = new Request.Builder()
                            .url(endpoint + "/credentials")
                            .header("Authorization", "Bearer " + token)
                            .post(RequestBody.create(body, MediaType.parse("application/json")))
                            .build();

                    try (var ignored = new OkHttpClient().newCall(rq).execute()) {
                        // we don't care about the response here
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }, 500, MILLISECONDS);

        scheduledExecutorService.shutdown();
    }

    private record RequestStatus(CredentialRequestMessage credentialRequest, String status) {
    }
}

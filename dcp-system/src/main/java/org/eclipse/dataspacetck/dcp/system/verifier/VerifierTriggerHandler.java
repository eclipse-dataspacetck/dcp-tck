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

package org.eclipse.dataspacetck.dcp.system.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.eclipse.dataspacetck.core.api.system.HandlerResponse;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.TokenValidationService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.handler.AbstractProtocolHandler;
import org.eclipse.dataspacetck.dcp.system.message.DcpConstants;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.MetadataReference;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.revocation.CredentialRevocationService;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.Optional.ofNullable;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.NULL_BODY;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VC;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VERIFIABLE_CREDENTIAL_CLAIM;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VP;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.system.util.Parsers.parseBearerToken;
import static org.eclipse.dataspacetck.dcp.system.util.Validators.validateBearerTokenHeader;

public class VerifierTriggerHandler extends AbstractProtocolHandler {
    private final TokenValidationService tokenService;
    private final ObjectMapper objectMapper;
    private final OkHttpClient httpClient;
    private final KeyService keyService;
    private final String verifierDid;
    private final TokenValidationService credentialValidationService;
    private final CredentialRevocationService credentialRevocationService;

    public VerifierTriggerHandler(TokenValidationService tokenService, ObjectMapper objectMapper,
                                  KeyService keyService, String verifierDid,
                                  TokenValidationService credentialValidationService, CredentialRevocationService credentialRevocationService) {
        super("/credential-schemas/membership-credential-schema.json");
        this.tokenService = tokenService;
        this.objectMapper = objectMapper;
        this.keyService = keyService;
        this.verifierDid = verifierDid;
        this.credentialValidationService = credentialValidationService;
        this.credentialRevocationService = credentialRevocationService;
        this.httpClient = new OkHttpClient();
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {

        var tokenHeaders = headers.get(AUTHORIZATION);
        if (tokenHeaders == null || tokenHeaders.isEmpty()) {
            return new HandlerResponse(401, NULL_BODY);
        }

        var unparsedToken = tokenHeaders.get(0);
        if (!validateBearerTokenHeader(unparsedToken)) {
            return new HandlerResponse(401, NULL_BODY);
        }

        var idToken = parseBearerToken(unparsedToken);
        var jwtResult = tokenService.validateToken(idToken);
        if (jwtResult.failed()) {
            return new HandlerResponse(401, NULL_BODY);
        }

        var jwt = jwtResult.getContent();
        try {
            var accessToken = jwt.getJWTClaimsSet().getClaimAsString(TOKEN);
            var bearerDid = jwt.getJWTClaimsSet().getIssuer();

            var verifierIdToken = createIdToken(accessToken, bearerDid);


            var endpoint = resolveCredentialServiceEndpoint(bearerDid);
            var presentationQueryRequest = new Request.Builder()
                    .url(endpoint + PRESENTATION_QUERY_PATH)
                    .header(AUTHORIZATION, "Bearer " + verifierIdToken)
                    .post(RequestBody.create(objectMapper.writeValueAsString(createPresentationMessage()), MediaType.parse(DcpConstants.JSON_CONTENT_TYPE)))
                    .build();

            try (var response = httpClient.newCall(presentationQueryRequest).execute()) {
                if (response.isSuccessful()) {
                    var presentationResponse = objectMapper.readValue(response.body().byteStream(), PresentationResponseMessage.class);
                    return verifyPresentationResponse(presentationResponse);
                }
                return toHandlerResponse(response);
            }

        } catch (IOException | ParseException e) {
            return new HandlerResponse(401, e.getMessage());
        }


    }

    @SuppressWarnings("unchecked")
    private HandlerResponse verifyPresentationResponse(PresentationResponseMessage presentationResponse) {
        if (presentationResponse.presentations().isEmpty()) {
            return new HandlerResponse(401, "empty presentation array");
        }
        try {
            for (String presentation : presentationResponse.presentations()) {
                var result = tokenService.validateToken(presentation);
                if (result.failed()) {
                    return new HandlerResponse(401, result.getFailure());
                }
                var presentationClaims = result.getContent().getJWTClaimsSet();
                if (!presentationClaims.getAudience().contains(verifierDid)) {
                    return new HandlerResponse(401, "missing audience: " + verifierDid);
                }
                if (!presentationClaims.getIssuer().equals(presentationClaims.getSubject())) {
                    return new HandlerResponse(401, "iss != sub");
                }
                var vpToken = result.getContent().getJWTClaimsSet().getJSONObjectClaim(VP);
                if (vpToken == null) {
                    return new HandlerResponse(401, "missing 'vp' claim");
                }
                var credentials = (List<String>) vpToken.get(VERIFIABLE_CREDENTIAL_CLAIM);

                // technically, empty credentials is OK, but we specifically requested the MembershipCredential earlier
                if (credentials.isEmpty()) {
                    return new HandlerResponse(401, "No credentials received");
                }
                for (var credential : credentials) {
                    var credentialResult = validateCredential(presentationClaims.getIssuer(), credential);
                    if (credentialResult.failed()) {
                        return new HandlerResponse(401, credentialResult.getFailure());
                    }
                }

            }
            return new HandlerResponse(200, NULL_BODY);

        } catch (ParseException e) {
            return new HandlerResponse(401, e.getMessage());
        }
    }

    private @NotNull Result<Void> validateCredential(String presentationHolder, String credential) {
        // 5.4.3.2
        var tokenResult = credentialValidationService.validateToken(credential);
        if (tokenResult.failed()) {
            return Result.failure(tokenResult.getFailure());
        }

        try {
            var vc = objectMapper.convertValue(tokenResult.getContent().getJWTClaimsSet().getJSONObjectClaim(VC), VerifiableCredential.class);
            // 5.4.3.4 all credential subject IDs must match the holder ID

            var match = ofNullable(vc.getCredentialSubject().get("id"))
                    .map(Object::toString)
                    .map(id -> id.equals(presentationHolder))
                    .orElse(true);
            if (!match) {
                return Result.failure("Not all credential subject IDs match the holder ID");
            }

            if (vc.getExpirationDate() != null && Instant.parse(vc.getExpirationDate()).isBefore(now())) {
                return Result.failure("Credential is expired");
            }

            if (Instant.parse(vc.getIssuanceDate()).isAfter(now())) {
                return Result.failure("Credential is not yet valid");
            }

            // validate schema

            // check revocation - this is a shortcut, bypassing credential resolution through HTTP
            if (vc.getCredentialStatus() != null) {
                var index = vc.getCredentialStatus().getExtensibleProperties().get("statusListIndex");
                var ix = Integer.parseInt(index.toString());
                var status = credentialRevocationService.isRevoked(ix);
                if (status) {
                    return Result.failure("Credential is revoked");
                }
            }

            var isValidSchema = ofNullable(vc.getCredentialSchema())
                    .map(MetadataReference::getId)
                    .map(credentialSchemaUrl -> {
                        var validationMessages = schema.validate(objectMapper.convertValue(vc.getCredentialSubject(), JsonNode.class));
                        return validationMessages.isEmpty();
                    })
                    .orElse(true);

            if (!isValidSchema) {
                return Result.failure("Credential schema validation failed");
            }
        } catch (ParseException e) {
            return Result.failure(e.getMessage());
        }

        return Result.success();

    }

    private String createIdToken(String accessToken, String audience) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .subject(verifierDid)
                .audience(audience)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, accessToken)
                .build();

        return keyService.sign(emptyMap(), claimSet);
    }

    private HandlerResponse toHandlerResponse(Response response) {
        if (response.isSuccessful()) {
            return new HandlerResponse(200, NULL_BODY);
        }
        return new HandlerResponse(response.code(), response.message());
    }

    private Map<String, Object> createPresentationMessage() {
        return DcpMessageBuilder.newInstance()
                .type(PRESENTATION_QUERY_MESSAGE)
                .property(SCOPE, List.of(MEMBERSHIP_SCOPE))
                .build();
    }

    private String resolveCredentialServiceEndpoint(String bearerDid) {
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(bearerDid);
        return document.getServiceEntry(CREDENTIAL_SERVICE_TYPE).serviceEndpoint();
    }
}

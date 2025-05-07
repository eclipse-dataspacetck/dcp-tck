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

import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.TokenValidationService;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

public class IssuerServiceImpl implements IssuerService {
    private final KeyService issuerKeyService;
    private final TokenValidationService issuerTokenValidationService;

    public IssuerServiceImpl(KeyService issuerKeyService, TokenValidationService issuerTokenValidationService) {
        this.issuerKeyService = issuerKeyService;
        this.issuerTokenValidationService = issuerTokenValidationService;
    }

    @Override
    public Result<Map<String, Object>> processCredentialRequest(String idTokenJwt, Map<String, Object> credentialRequestMessage) {

        var validationResult = issuerTokenValidationService.validateToken(idTokenJwt);
        if (!validationResult.succeeded()) {
            return failure(validationResult.getFailure());
        }

        var jwt = validationResult.getContent();
        String issuerDid;
        String holderDid;
        try {
            issuerDid = jwt.getJWTClaimsSet().getAudience().get(0);
            holderDid = jwt.getJWTClaimsSet().getIssuer();

        } catch (ParseException e) {
            return failure("Error parsing holder's token: " + e.getMessage());
        }
        var gen = new JwtCredentialGenerator(issuerDid, issuerKeyService);

        //noinspection unchecked
        var credentials = ((List<Map<String, Object>>) credentialRequestMessage.get("credentials")).stream()
                .map(cred -> Map.of(
                        "credentialType", cred.get("credentialType"),
                        "format", cred.get("format"),
                        "payload", gen.generateCredential(VerifiableCredential.Builder.newInstance()
                                .credentialSubject(Map.of("id", holderDid))
                                .id(randomUUID().toString())
                                .issuanceDate(Instant.now().toString())
                                .issuer(issuerDid)
                                .type(List.of(cred.get("credentialType").toString()))
                                .credentialSubject(Map.of("id", UUID.randomUUID().toString(), "bar", "baz"))
                                .build()).getContent()
                )).toList();
        var correlation = credentialRequestMessage.get("holderPid");
        if (correlation == null) {
            return failure("Missing holderPid");
        }

        var credentialsMsg = DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_MESSAGE_TYPE)
                .property("requestId", correlation)
                .property("issuerPid", UUID.randomUUID().toString())
                .property("holderPid", correlation)
                .property("credentials", credentials)
                .property("status", "ISSUED")
                .build();
        return success(credentialsMsg);
    }
}

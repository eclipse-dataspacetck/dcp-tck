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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.dcp.system.cs.TokenValidationService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.model.did.VerificationMethod;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.jetbrains.annotations.NotNull;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * This is a token validation service, specifically designed to validate JWT-VCs as it ignores the aud, iss and sub claims
 */
public class BaseTokenValidationService implements TokenValidationService {
    private final Map<String, String> usedJts = new ConcurrentHashMap<>();

    @Override
    public Result<JWT> validateToken(String credentialToken) {
        try {
            var jwt = SignedJWT.parse(credentialToken);

            var claims = jwt.getJWTClaimsSet();

            // no audience, iss or sub validation

            var verificationMethod = validateClaims(claims, jwt.getHeader());
            if (verificationMethod.failed()) {
                return failure(verificationMethod.getFailure());
            }
            return verifySignature(jwt, verificationMethod.getContent());

        } catch (JOSEException | ParseException e) {
            return failure("Invalid JWT: " + e.getMessage());
        }
    }

    @NotNull
    protected Result<VerificationMethod> validateClaims(JWTClaimsSet claims, JWSHeader header) throws ParseException, JOSEException {
        var kid = header.getKeyID();
        var jti = claims.getJWTID();
        if (jti == null) {
            return failure("JTI not specified");
        }

        if (usedJts.containsKey(jti)) {
            return failure("JTI already used");
        }
        usedJts.put(jti, jti);

        if (claims.getExpirationTime() == null) {
            return failure("Expiration not specified");
        }

        if (claims.getExpirationTime().before(new Date())) {
            return failure("Token has expired");
        }

        if (claims.getIssueTime() == null) {
            return failure("IAT not specified");
        }

        if (claims.getIssueTime().after(new Date())) {
            return failure("Token issued in the future");
        }

        if (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().after(new Date())) {
            return failure("Token used before start");
        }
        var parts = kid.split("#");
        if (parts.length != 1 && parts.length != 2) {
            return failure("Invalid kid: " + kid);
        }
        var issuerDid = parts[0];
        var client = new DidClient(false);
        var didDocument = client.resolveDocument(issuerDid);

        VerificationMethod method;
        if (parts.length == 1) {
            if (didDocument.getVerificationMethods().size() != 1) {
                return failure("Since no key id was specified, the DID document must have exactly one verification method");
            }
            method = didDocument.getVerificationMethods().get(0);
        } else {
            var result = didDocument.getVerificationMethod("#" + parts[1]);
            if (result.failed()) {
                return failure(result.getFailure());
            }
            method = result.getContent();
        }

        return success(method);

    }

    @NotNull
    protected Result<JWT> verifySignature(SignedJWT jwt, VerificationMethod method) throws ParseException, JOSEException {
        var key = JWK.parse(method.getPublicKeyJwk());
        var result = jwt.verify(createVerifier(key.toECKey().toPublicKey()));
        return result ? success(jwt) : failure("JWT verification failed");
    }
}

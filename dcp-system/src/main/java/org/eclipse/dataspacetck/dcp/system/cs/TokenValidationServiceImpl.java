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

package org.eclipse.dataspacetck.dcp.system.cs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.model.did.VerificationMethod;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.Date;

import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

/**
 * Default implementation.
 */
public class TokenValidationServiceImpl implements TokenValidationService {
    private final String audience;

    public TokenValidationServiceImpl(String audience) {
        this.audience = audience;
    }

    @Override
    public Result<JWT> validateToken(String token) {
        try {
            var jwt = SignedJWT.parse(token);
            var claims = jwt.getJWTClaimsSet();

            var aud = claims.getAudience();
            if (aud.isEmpty()) {
                return failure("Audience is empty");
            } else if (!aud.contains(audience)) {
                return failure("Audience does not match: " + aud);
            }

            if (!claims.getIssuer().equals(claims.getSubject())) {
                return failure("Issuer and subject do not match");
            }

            if (claims.getJWTID() == null) {
                return failure("JTI not specified");
            }

            if (claims.getExpirationTime() == null) {
                return failure("Expiration not specified");
            }

            if (claims.getExpirationTime().before(new Date())) {
                return failure("Token has expired");
            }

            if (claims.getIssueTime() == null) {
                return failure("IAT not specified");
            }

            if (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().after(new Date())) {
                return failure("Token used before start");
            }

            var kid = jwt.getHeader().getKeyID();
            var parts = kid.split("#");
            if (parts.length != 1 && parts.length != 2) {
                return failure("Invalid kid: " + jwt.getHeader().getKeyID());
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
                method = didDocument.getVerificationMethod(parts[1]);
            }

            if (!claims.getSubject().equals(didDocument.getId())) {
                return failure("Token sub claim must equal DID document id");
            }
            var key = JWK.parse(method.getPublicKeyJwk());
            var result = jwt.verify(createVerifier(key.toECKey().toPublicKey()));
            return result ? success(jwt) : failure("JWT verification failed");
        } catch (java.text.ParseException | JOSEException e) {
            return failure("Invalid JWT: " + e.getMessage());
        }
    }
}

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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.dcp.system.model.did.VerificationMethod;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.system.verifier.BaseTokenValidationService;
import org.jetbrains.annotations.NotNull;

import java.text.ParseException;

import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;

/**
 * Default implementation.
 */
public class TokenValidationServiceImpl extends BaseTokenValidationService {
    private final String audience;

    public TokenValidationServiceImpl(String audience) {
        this.audience = audience;
    }

    @NotNull
    @Override
    protected Result<VerificationMethod> validateClaims(JWTClaimsSet claims, JWSHeader header) throws ParseException, JOSEException {
        var aud = claims.getAudience();
        if (aud.isEmpty()) {
            return failure("Audience is empty");
        } else if (!aud.contains(audience)) {
            return failure("Audience does not match: " + aud);
        }

        if (!claims.getIssuer().equals(claims.getSubject())) {
            return failure("Issuer and subject do not match");
        }
        return super.validateClaims(claims, header);
    }
}

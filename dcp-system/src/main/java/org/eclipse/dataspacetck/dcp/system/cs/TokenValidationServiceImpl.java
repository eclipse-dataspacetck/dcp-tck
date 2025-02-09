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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.dcp.system.service.Result;

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
            var aud = jwt.getJWTClaimsSet().getAudience();
            if (aud.isEmpty()) {
                return failure("Audience is empty");
            } else if (!aud.contains(audience)) {
                return failure("Audience does not match: " + aud);
            }
            return success(jwt);
        } catch (java.text.ParseException e) {
            return failure("Invalid JWT: " + e.getMessage());
        }
    }
}

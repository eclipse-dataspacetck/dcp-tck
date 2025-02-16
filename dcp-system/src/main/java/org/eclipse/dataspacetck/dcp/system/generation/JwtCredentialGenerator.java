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

package org.eclipse.dataspacetck.dcp.system.generation;

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.Date;
import java.util.Map;

import static java.lang.String.format;
import static java.time.Instant.now;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat.VC1_0_JWT;

/**
 * Generates a verifiable credential using the JWT format.
 */
public class JwtCredentialGenerator implements CredentialGenerator {
    private final String issuerDid;
    private KeyService keyService;

    public JwtCredentialGenerator(String issuerDid, KeyService keyService) {
        this.issuerDid = issuerDid;
        this.keyService = keyService;
    }

    @Override
    public CredentialFormat getFormat() {
        return VC1_0_JWT;
    }

    @Override
    public Result<String> generateCredential(VerifiableCredential credential) {
        var now = new Date();
        if (!issuerDid.equals(credential.getIssuer())) {
            throw new RuntimeException(format("Credential issuer '%s' not equal to issuer DID: %s", credential.getIssuer(), issuerDid));
        }
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .subject(credential.getId())
                .claim("jti", randomUUID())
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(Date.from(now().plusSeconds(300)))
                .claim("vc", credential.toMap())
                .build();
        var keyId = issuerDid + "#" + keyService.getPublicKey().getKeyID();
        return Result.success(keyService.sign(Map.of("kid", keyId), claims));
    }
}

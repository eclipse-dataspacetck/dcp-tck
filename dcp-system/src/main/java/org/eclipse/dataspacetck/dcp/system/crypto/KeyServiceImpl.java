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

package org.eclipse.dataspacetck.dcp.system.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Map;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.ES256;

/**
 * Default implementation.
 */
public class KeyServiceImpl implements KeyService {
    private final ECKey key;

    public KeyServiceImpl(ECKey key) {
        this.key = key;
    }

    @Override
    public JWK getPublicKey() {
        return key.toPublicJWK();
    }

    @Override
    public String sign(Map<String, String> headers, JWTClaimsSet claims) {
        var header = new JWSHeader.Builder(ES256).type(JWT);
        if (!headers.containsKey("kid")) {
            header.keyID(claims.getClaim("iss") + "#" + key.getKeyID());
        }
        headers.forEach((k, v) -> {
            if ("kid".equals(k)) {
                header.keyID(v);
            } else {
                header.customParam(k, v);
            }
        });
        try {
            var signedJwt = new SignedJWT(header.build(), claims);
            signedJwt.sign(new ECDSASigner(key.toECPrivateKey()));
            return signedJwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}

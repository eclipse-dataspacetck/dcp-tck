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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import static java.util.UUID.randomUUID;

/**
 * Methods for working with keys.
 */
public class Keys {
    private static final int KEY_SIZE = 2048;

    public static RSAKey generateRsaKey() {
        try {
            return new RSAKeyGenerator(KEY_SIZE)
                    .keyID(randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public static ECKey generateEcKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

}

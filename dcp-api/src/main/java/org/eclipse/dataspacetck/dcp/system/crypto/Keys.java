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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.jetbrains.annotations.NotNull;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EdECPoint;

import static com.nimbusds.jose.util.Base64URL.encode;
import static java.util.UUID.randomUUID;

/**
 * Methods for working with keys.
 */
public class Keys {
    private static final int KEY_SIZE = 2048;

    private static final String ALGORITHM_EC = "ec";
    private static final String ALGORITHM_ECDSA = "ecdsa";
    private static final String ALGORITHM_EDDSA = "eddsa";
    private static final String ALGORITHM_ED25519 = "ed25519";
    private static final String ALGORITHM_RSA = "rsa";

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

    public static JWSVerifier createVerifier(PublicKey publicKey) {
        var algorithm = publicKey.getAlgorithm().toLowerCase();
        try {
            return switch (algorithm) {
                case ALGORITHM_EC, ALGORITHM_ECDSA -> createEcdsaVerifier((ECPublicKey) publicKey);
                case ALGORITHM_EDDSA, ALGORITHM_ED25519 -> createEdDsaVerifier(publicKey);
                case ALGORITHM_RSA -> new RSASSAVerifier((RSAPublicKey) publicKey);
                default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            };
        } catch (JOSEException e) {
            throw new RuntimeException("Error creating verifier for: " + algorithm, e);
        }
    }

    public static ECDSAVerifier createEcdsaVerifier(ECPublicKey publicKey) throws JOSEException {
        var verifier = new ECDSAVerifier(publicKey);
        verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        return verifier;
    }

    public static Ed25519Verifier createEdDsaVerifier(PublicKey publicKey) throws JOSEException {
        var edKey = (EdECPublicKey) publicKey;
        var curve = Curve.parse(edKey.getParams().getName());
        var encodedX = encodePublicKey(edKey.getPoint());
        var keyPair = new OctetKeyPair.Builder(curve, encodedX).build();
        return new Ed25519Verifier(keyPair);
    }

    /**
     * Encodes the public key as Base64.
     */
    @NotNull
    private static Base64URL encodePublicKey(EdECPoint point) {
        var bytes = reverse(point.getY().toByteArray());
        if (point.isXOdd()) {
            var mask = (byte) 128;
            bytes[bytes.length - 1] ^= mask;
        }
        return encode(bytes);
    }

    private static byte[] reverse(byte[] array) {
        for (var i = 0; i < array.length / 2; i++) {
            var temp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = temp;
        }
        return array;
    }
}

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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Map;

/**
 * Manages cryptographic keys and performs signing for a holder or verifier.
 */
public interface KeyService {

    /**
     * Returns the public key.
     */
    JWK getPublicKey();

    /**
     * Signs the JWT.
     */
    String sign(Map<String, String> headers, JWTClaimsSet claims);

}

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

package org.eclipse.dataspacetck.dcp.system.sts;

import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.List;

/**
 * Obtains an authz token from the holder's STS.
 */
public interface StsClient {

    /**
     * Obtains the token
     *
     * @param bearerDid the bearer's DID to bind the token
     * @param scopes    requested scope
     */
    Result<String> obtainReadToken(String bearerDid, List<String> scopes);

    Result<String> obtainWriteToken(String bearerDid, String audience, KeyService keyService);
}

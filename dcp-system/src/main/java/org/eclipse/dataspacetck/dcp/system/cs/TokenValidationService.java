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
import org.eclipse.dataspacetck.dcp.system.service.Result;

/**
 * Validates a JWT token.
 */
public interface TokenValidationService {

    /**
     * Validates the token, returning a JWT representation.
     */
    Result<JWT> validateToken(String token);
}

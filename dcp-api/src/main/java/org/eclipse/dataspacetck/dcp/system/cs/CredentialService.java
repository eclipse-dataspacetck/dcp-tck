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

import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.io.InputStream;
import java.util.Map;

/**
 * Credential service used for testing.
 */
public interface CredentialService {

    /**
     * Processes a presentation query message.
     */
    Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message);

    /**
     * Writes issued credentials.
     */
    Result<Void> writeCredentials(String idTokenJwt, InputStream body);
}

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

import java.util.List;
import java.util.Map;

/**
 * Credential service used for testing.
 */
public interface CredentialService {

    Result<Map<String, Object>> presentationQueryMessage(String token, Map<String, Object> message);

    Result<Void> writeCredentials(String token, List<Map<String, Object>> message);
}

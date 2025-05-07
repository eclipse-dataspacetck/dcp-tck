/*
 *  Copyright (c) 2025 Metaform Systems Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems Inc. - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.system.issuer;

import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.Map;

/**
 * Issuer service used for testing when a real System-under-Test is not available.
 */
public interface IssuerService {

    Result<Void> processCredentialRequest(String idTokenJwt, Map<String, Object> credentialRequestMessage);
}

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

package org.eclipse.dataspacetck.dcp.system.did;

import org.eclipse.dataspacetck.dcp.system.model.did.DidDocument;
import org.eclipse.dataspacetck.dcp.system.service.Result;

/**
 * Manages the DID document for a holder or verifier.
 */
public interface DidService {
    String DID_CONTEXT = "https://www.w3.org/ns/did/v1";

    Result<DidDocument> resolveDidDocument();

}

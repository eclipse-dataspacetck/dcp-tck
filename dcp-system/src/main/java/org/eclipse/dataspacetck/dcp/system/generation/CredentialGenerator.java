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

package org.eclipse.dataspacetck.dcp.system.generation;

import org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.service.Result;

/**
 * Generates credentials according to a {@link CredentialFormat}.
 */
public interface CredentialGenerator {

    /**
     * The format supported by the generator.
     */
    CredentialFormat getFormat();

    /**
     * Generates a signed credential.
     */
    Result<String> generateCredential(VerifiableCredential credential);

}

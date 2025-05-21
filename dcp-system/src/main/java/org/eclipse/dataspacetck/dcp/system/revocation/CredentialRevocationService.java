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

package org.eclipse.dataspacetck.dcp.system.revocation;

import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;

public interface CredentialRevocationService {

    void setRevoked(int statusListIndex);

    VerifiableCredential createStatusListCredential();

    boolean isRevoked(int statusListIndex);

    String getCredentialId();

    String getAddress();

    String getStatusEntryType();
}

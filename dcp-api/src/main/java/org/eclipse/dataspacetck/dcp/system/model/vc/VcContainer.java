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

package org.eclipse.dataspacetck.dcp.system.model.vc;

import static java.util.Objects.requireNonNull;

/**
 * Holds a raw VC, its deserialized representation, and the format.
 */
public record VcContainer(String rawCredential, VerifiableCredential credential, CredentialFormat format) {
    public VcContainer {
        requireNonNull(rawCredential, "rawCredential");
        requireNonNull(credential, "credential");
        requireNonNull(format, "format");
    }
}

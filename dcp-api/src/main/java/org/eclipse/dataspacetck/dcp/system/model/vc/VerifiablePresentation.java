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

import org.eclipse.dataspacetck.dcp.system.model.ExtensibleModel;

import java.util.ArrayList;
import java.util.List;

/**
 * A verifiable presentation.
 */
public abstract class VerifiablePresentation<T> extends ExtensibleModel {
    protected List<String> type;
    protected List<T> verifiableCredential = new ArrayList<>();

    public List<String> getType() {
        return type;
    }

    public List<T> getVerifiableCredential() {
        return verifiableCredential;
    }
}
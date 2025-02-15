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

import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.List;

/**
 * Generates a verifiable presentation.
 */
public interface PresentationGenerator {
    enum PresentationFormat {
        JWT, LD
    }

    /**
     * Returns the VP format supported by this generator.
     */
    PresentationFormat getFormat();

    /**
     * Generates a presentation containing the given credentials.
     */
    Result<String> generatePresentation(String audience, String holderDid, List<VcContainer> credentials);

}

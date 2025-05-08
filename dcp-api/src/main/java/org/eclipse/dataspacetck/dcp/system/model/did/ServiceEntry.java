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

package org.eclipse.dataspacetck.dcp.system.model.did;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A DID service entry.
 */
public record ServiceEntry(String id, String type, String serviceEndpoint) {
    public ServiceEntry(@JsonProperty("id") String id,
                        @JsonProperty("type") String type,
                        @JsonProperty("serviceEndpoint") String serviceEndpoint) {
        this.id = id;
        this.type = type;
        this.serviceEndpoint = serviceEndpoint;
    }
}

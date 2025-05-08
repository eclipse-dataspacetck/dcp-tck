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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class CredentialStatus {
    private final String type = "CredentialStatus";

    @JsonProperty("issuerPid")
    private String issuerPid;

    @JsonProperty("holderPid")
    private String holderPid;

    @JsonProperty("status")
    private String status;

    public boolean validate() {
        return List.of("ISSUED", "RECEIVED", "REJECTED").contains(status) &&
                issuerPid != null &&
                holderPid != null;
    }

    public String getType() {
        return type;
    }

    public String getIssuerPid() {
        return issuerPid;
    }

    public String getHolderPid() {
        return holderPid;
    }

    public String getStatus() {
        return status;
    }
}

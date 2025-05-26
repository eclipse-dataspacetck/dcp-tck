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
import org.eclipse.dataspacetck.dcp.system.cs.CredentialObject;

import java.util.ArrayList;
import java.util.Collection;

public class CredentialRequestMessage {
    @JsonProperty("type")
    private String type;

    @JsonProperty("holderPid")
    private String holderPid;

    @JsonProperty("credentials")
    private Collection<CredentialObject> credentials = new ArrayList<>();

    public String getType() {
        return type;
    }

    public String getHolderPid() {
        return holderPid;
    }

    public Collection<CredentialObject> getCredentials() {
        return credentials;
    }

    public boolean validate() {
        return type != null && holderPid != null && credentials != null && !credentials.isEmpty() && credentials.stream().allMatch(CredentialObject::validate);
    }

}

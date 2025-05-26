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

package org.eclipse.dataspacetck.dcp.system.cs;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Collection;

public class CredentialOfferMessage {
    @JsonProperty(value = "type", required = true)
    private String type;
    @JsonProperty(value = "issuer", required = true)
    private String issuer;

    @JsonProperty(value = "credentials", required = true)
    private Collection<CredentialObject> credentials = new ArrayList<>();


    public String getType() {
        return type;
    }

    public String getIssuer() {
        return issuer;
    }

    public Collection<CredentialObject> getCredentials() {
        return credentials;
    }

    public boolean validate() {
        return type != null && issuer != null && credentials != null && !credentials.isEmpty() &&
                credentials.stream().allMatch(CredentialObject::validate);
    }

}

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
import java.util.List;

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_MESSAGE_TYPE;

public class CredentialMessage {
    @JsonProperty(value = "credentials", required = true)
    private final List<CredentialContainer> credentials = new ArrayList<>();
    @JsonProperty(value = "issuerPid", required = true)
    private String issuerPid;
    @JsonProperty(value = "holderPid", required = true)
    private String holderPid;
    @JsonProperty(value = "status", required = true, defaultValue = "ISSUED")
    private String status;
    @JsonProperty(value = "type", required = true)
    private String type = CREDENTIAL_MESSAGE_TYPE;

    private CredentialMessage() {
        // Default constructor for deserialization
    }

    public boolean validate() {
        return List.of("ISSUED", "REJECTED").contains(status) &&
                issuerPid != null &&
                holderPid != null &&
                !credentials.isEmpty();
    }

    public List<CredentialContainer> getCredentials() {
        return credentials;
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

    public String getType() {
        return type;
    }

    public static class Builder {
        private final CredentialMessage instance = new CredentialMessage();

        public static Builder newInstance() {
            return new Builder();
        }

        public Builder credentials(List<CredentialContainer> credentials) {
            instance.credentials.addAll(credentials);
            return this;
        }

        public Builder issuerPid(String issuerPid) {
            instance.issuerPid = issuerPid;
            return this;
        }

        public Builder holderPid(String holderPid) {
            instance.holderPid = holderPid;
            return this;
        }

        public Builder status(String status) {
            instance.status = status;
            return this;
        }

        public Builder type(String type) {
            instance.type = type;
            return this;
        }

        public CredentialMessage build() {
            return instance;
        }
    }

    public record CredentialContainer(String credentialType, String payload, String format) {
    }
}

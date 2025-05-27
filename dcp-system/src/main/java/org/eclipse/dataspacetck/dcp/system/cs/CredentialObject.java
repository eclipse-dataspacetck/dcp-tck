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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CredentialObject {
    @JsonProperty(value = "bindingMethods")
    private final List<String> bindingMethods = new ArrayList<>();
    @JsonProperty(value = "profile")
    private String profile;
    @JsonProperty(value = "issuancePolicy")
    private final Map<String, Object> issuancePolicy = new HashMap<>();
    @JsonProperty(value = "id", required = true)
    private String id;
    @JsonProperty(value = "type")
    private String type;
    @JsonProperty(value = "credentialType")
    private String credentialType;
    @JsonProperty(value = "offerReason")
    private String offerReason;
    @JsonProperty(value = "credentialSchema")
    private String credentialSchema;

    public List<String> getBindingMethods() {
        return bindingMethods;
    }

    public String getProfile() {
        return profile;
    }

    public Map<String, Object> getIssuancePolicy() {
        return issuancePolicy;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public String getOfferReason() {
        return offerReason;
    }

    public String getCredentialSchema() {
        return credentialSchema;
    }

    public boolean validate() {
        if (type == null && credentialType == null && id != null) {
            return true;
        }
        return type != null && credentialType != null && id != null;
    }

    public static class Builder {
        private final CredentialObject credentialObject;

        private Builder() {
            credentialObject = new CredentialObject();
        }

        public static Builder newInstance() {
            return new Builder();
        }

        public Builder bindingMethods(List<String> bindingMethods) {
            credentialObject.bindingMethods.addAll(bindingMethods);
            return this;
        }

        public Builder profile(String profile) {
            credentialObject.profile = profile;
            return this;
        }

        public Builder issuancePolicy(Map<String, Object> issuancePolicy) {
            credentialObject.issuancePolicy.putAll(issuancePolicy);
            return this;
        }

        public Builder id(String id) {
            credentialObject.id = id;
            return this;
        }

        public Builder type(String type) {
            credentialObject.type = type;
            return this;
        }

        public Builder credentialType(String credentialType) {
            credentialObject.credentialType = credentialType;
            return this;
        }

        public Builder offerReason(String offerReason) {
            credentialObject.offerReason = offerReason;
            return this;
        }

        public Builder credentialSchema(String credentialSchema) {
            credentialObject.credentialSchema = credentialSchema;
            return this;
        }

        public CredentialObject build() {
            return credentialObject;
        }
    }
}

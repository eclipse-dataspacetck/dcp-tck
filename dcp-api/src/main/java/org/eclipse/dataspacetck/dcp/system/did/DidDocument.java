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
package org.eclipse.dataspacetck.dcp.system.did;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Models a DID document.
 */
@JsonDeserialize(builder = DidDocument.Builder.class)
public class DidDocument {
    private String id;

    @JsonProperty("@context")
    private List<String> context = new ArrayList<>();

    @JsonProperty("service")
    private List<ServiceEntry> services = new ArrayList<>();

    @JsonProperty("verificationMethod")
    private List<VerificationMethod> verificationMethods = new ArrayList<>();

    private Map<String, Object> extensibleProperties = new LinkedHashMap<>();

    public List<String> getContext() {
        return context;
    }

    public String getId() {
        return id;
    }

    public List<ServiceEntry> getServices() {
        return services;
    }

    public List<VerificationMethod> getVerificationMethods() {
        return verificationMethods;
    }

    @JsonAnyGetter
    public Map<String, Object> getExtensibleProperties() {
        return extensibleProperties;
    }

    public ServiceEntry getServiceEntry(String type) {
        return services.stream()
                .filter(s -> s.getType().equals(type))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No service found for type " + type));
    }

    public VerificationMethod getVerificationMethod(String id) {
        return verificationMethods.stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No verification method found for id " + id));
    }

    private DidDocument() {
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {
        private DidDocument document;

        @JsonCreator
        public static Builder newInstance() {
            return new Builder();
        }

        public Builder id(String id) {
            document.id = id;
            return this;
        }

        public Builder context(List<String> context) {
            document.context.addAll(context);
            return this;
        }

        public Builder service(List<ServiceEntry> services) {
            document.services.addAll(services);
            return this;
        }

        public Builder verificationMethod(List<VerificationMethod> methods) {
            document.verificationMethods.addAll(methods);
            return this;
        }

        @JsonAnySetter
        public void setExtensibleProperty(String key, Object value) {
            this.document.extensibleProperties.put(key, value);
        }

        public DidDocument build() {
            return document;
        }

        private Builder() {
            document = new DidDocument();
        }
    }
}

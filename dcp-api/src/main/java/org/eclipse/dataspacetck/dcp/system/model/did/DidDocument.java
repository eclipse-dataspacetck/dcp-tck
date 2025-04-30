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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.eclipse.dataspacetck.dcp.system.model.ExtensibleModel;

import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Models a DID document.
 */
@JsonDeserialize(builder = DidDocument.Builder.class)
public class DidDocument extends ExtensibleModel {
    private String id;

    @JsonProperty("service")
    private List<ServiceEntry> services = new ArrayList<>();

    @JsonProperty("verificationMethod")
    private List<VerificationMethod> verificationMethods = new ArrayList<>();

    private DidDocument() {
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

    public ServiceEntry getServiceEntry(String type) {
        return services.stream()
                .filter(s -> s.getType().equals(type))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No service found for type " + type));
    }

    public VerificationMethod getVerificationMethod(String id) {

        return verificationMethods.stream()
                .filter(m -> m.getId().equals(id) || m.getId().equals(this.id + id) || m.getId().equals(this.id + "#" + id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No verification method found for id " + id));
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder extends ExtensibleModel.Builder<Builder> {
        private final DidDocument document;

        private Builder() {
            document = new DidDocument();
            setModel(document);
        }

        @JsonCreator
        public static Builder newInstance() {
            return new Builder();
        }

        public Builder id(String id) {
            document.id = id;
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

        public DidDocument build() {
            requireNonNull(document.id, "id");
            return document;
        }
    }
}

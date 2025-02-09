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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A DID verification method.
 */
@JsonDeserialize(builder = VerificationMethod.Builder.class)
public class VerificationMethod {
    private String id;
    private String type;
    private String controller;
    private Map<String, Object> publicKeyJwk = new LinkedHashMap<>();

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getController() {
        return controller;
    }

    public Map<String, Object> getPublicKeyJwk() {
        return publicKeyJwk;
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {
        private VerificationMethod method;

        @JsonCreator
        public static Builder newInstance() {
            return new Builder();
        }

        public Builder id(String id) {
            method.id = id;
            return this;
        }

        public Builder type(String type) {
            method.type = type;
            return this;
        }

        public Builder controller(String controller) {
            method.controller = controller;
            return this;
        }

        public Builder publicKeyJwk(Map<String, Object> jwk) {
            method.publicKeyJwk.putAll(jwk);
            return this;
        }

        public VerificationMethod build() {
            return method;
        }

        private Builder() {
            method = new VerificationMethod();
        }
    }
}


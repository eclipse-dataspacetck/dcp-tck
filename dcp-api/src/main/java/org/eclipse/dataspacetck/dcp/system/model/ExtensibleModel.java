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

package org.eclipse.dataspacetck.dcp.system.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Model class that has extensible properties and a Json-Ld context.
 */
public class ExtensibleModel {
    @JsonProperty("@context")
    protected List<String> context = new ArrayList<>();

    protected Map<String, Object> extensibleProperties = new LinkedHashMap<>();

    public List<String> getContext() {
        return context;
    }

    @JsonAnyGetter
    public Map<String, Object> getExtensibleProperties() {
        return extensibleProperties;
    }

    public static class Builder<E extends Builder<E>> {
        private ExtensibleModel model;

        @SuppressWarnings("unchecked")
        public E context(List<String> context) {
            model.context.addAll(context);
            return (E) this;
        }

        @JsonAnySetter
        @SuppressWarnings("unchecked")
        public E setExtensibleProperty(String key, Object value) {
            this.model.extensibleProperties.put(key, value);
            return (E) this;
        }

        protected void setModel(ExtensibleModel model) {
            this.model = model;
        }
    }

}

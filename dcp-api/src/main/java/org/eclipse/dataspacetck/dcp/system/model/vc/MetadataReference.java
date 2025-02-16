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

package org.eclipse.dataspacetck.dcp.system.model.vc;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;

/**
 * Tracks credential metadata such as a schema or status.
 */
@JsonDeserialize(builder = MetadataReference.Builder.class)
public class MetadataReference {
    private String id;
    private String type;
    private Map<String, Object> extensibleProperties = new LinkedHashMap<>();

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public Map<String, Object> getExtensibleProperties() {
        return extensibleProperties;
    }

    public Map<String, Object> toMap() {
        var map = new LinkedHashMap<String, Object>();
        map.put(ID, id);
        map.put(TYPE, List.of(type));
        map.putAll(extensibleProperties);
        return map;
    }

    private MetadataReference() {
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {
        private MetadataReference reference;


        @JsonCreator
        public static Builder newInstance() {
            return new Builder();
        }

        public Builder id(String id) {
            reference.id = id;
            return this;
        }

        public Builder type(String type) {
            reference.type = type;
            return this;
        }

        @JsonAnySetter
        public Builder setExtensibleProperty(String key, Object value) {
            this.reference.extensibleProperties.put(key, value);
            return this;
        }

        public MetadataReference build() {
            requireNonNull(reference.id, "id");
            requireNonNull(reference.type, "type");
            return reference;
        }

        private Builder() {
            reference = new MetadataReference();
        }
    }

}

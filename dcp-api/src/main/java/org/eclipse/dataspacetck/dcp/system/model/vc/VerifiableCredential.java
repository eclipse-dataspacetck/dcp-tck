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

package org.eclipse.dataspacetck.dcp.system.model.vc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.eclipse.dataspacetck.dcp.system.model.ExtensibleModel;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CONTEXT;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialConstants.CONTEXT_V1;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialConstants.CONTEXT_V2;

/**
 * A verifiable credential.
 */
@JsonDeserialize(builder = VerifiableCredential.Builder.class)
public class VerifiableCredential extends ExtensibleModel {

    private final List<String> type = new ArrayList<>();
    private Map<String, Object> credentialSubject = new LinkedHashMap<>();
    private String id;
    private String issuer;
    private String issuanceDate;
    private String expirationDate;
    private MetadataReference credentialSchema;
    private MetadataReference credentialStatus;

    public String getId() {
        return id;
    }

    @JsonProperty
    public List<String> getType() {
        return type;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getIssuanceDate() {
        return issuanceDate;
    }

    public Map<String, Object> getCredentialSubject() {
        return credentialSubject;
    }

    public MetadataReference getCredentialSchema() {
        return credentialSchema;
    }

    public MetadataReference getCredentialStatus() {
        return credentialStatus;
    }

    public Map<String, Object> toMap() {
        var map = new LinkedHashMap<String, Object>();
        map.put(CONTEXT, id);
        map.put(ID, id);
        map.put(TYPE, type);
        map.put("issuer", issuer);
        map.put("issuanceDate", issuanceDate);
        map.put("expirationDate", expirationDate);
        if (credentialSchema != null) {
            map.put("credentialSchema", credentialSchema);
        }
        if (credentialSchema != null) {
            map.put("credentialSchema", credentialSchema.toMap());
        }
        if (credentialStatus != null) {
            map.put("credentialStatus", credentialStatus.toMap());
        }
        map.put("credentialSubject", credentialSubject);
        return map;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder extends ExtensibleModel.Builder<Builder> {
        private final VerifiableCredential credential;

        private Builder() {
            credential = new VerifiableCredential();
            setModel(credential);
        }

        @JsonCreator
        public static Builder newInstance() {
            return new Builder();
        }

        public Builder id(String id) {
            credential.id = id;
            return this;
        }

        public Builder type(List<String> type) {
            credential.type.addAll(type);
            return this;
        }

        public Builder issuer(String issuer) {
            credential.issuer = issuer;
            return this;
        }

        public Builder issuanceDate(String date) {
            credential.issuanceDate = date;
            return this;
        }

        public Builder expirationDate(String date) {
            credential.expirationDate = date;
            return this;
        }

        public Builder credentialSchema(MetadataReference credentialSchema) {
            credential.credentialSchema = credentialSchema;
            return this;
        }

        public Builder credentialStatus(MetadataReference status) {
            credential.credentialStatus = status;
            return this;
        }

        public Builder credentialSubject(Map<String, Object> subject) {
            credential.credentialSubject = subject;
            return this;
        }

        public VerifiableCredential build() {
            requireNonNull(credential.id, "id");
            if (credential.context.contains(CONTEXT_V1) && !credential.context.contains(CONTEXT_V2)) {
                credential.context.add(0, CONTEXT_V1);
            }
            return credential;
        }
    }
}
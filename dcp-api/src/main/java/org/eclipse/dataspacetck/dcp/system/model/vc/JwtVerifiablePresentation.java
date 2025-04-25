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
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.eclipse.dataspacetck.dcp.system.model.ExtensibleModel;

import java.util.List;

import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialConstants.CONTEXT_V1;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialConstants.CONTEXT_V2;

/**
 * A verifiable presentation encoded as a JWT.
 */
public class JwtVerifiablePresentation extends VerifiablePresentation<String> {

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder extends ExtensibleModel.Builder<Builder> {
        private final JwtVerifiablePresentation presentation;

        private Builder() {
            presentation = new JwtVerifiablePresentation();
            setModel(presentation);
        }

        @JsonCreator
        public static Builder newInstance() {
            return new Builder();
        }

        public Builder type(List<String> types) {
            presentation.type.addAll(types);
            return this;
        }

        public Builder verifiableCredential(List<String> credentials) {
            presentation.verifiableCredential.addAll(credentials);
            return this;
        }

        public VerifiablePresentation<String> build() {
            if (presentation.context.contains(CONTEXT_V1) && !presentation.context.contains(CONTEXT_V2)) {
                presentation.context.add(0, CONTEXT_V1);
            }
            return presentation;
        }
    }

}

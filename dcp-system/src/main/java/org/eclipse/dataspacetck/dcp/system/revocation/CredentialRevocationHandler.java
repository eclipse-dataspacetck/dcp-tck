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

package org.eclipse.dataspacetck.dcp.system.revocation;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.function.Function;

public record CredentialRevocationHandler(CredentialRevocationService revocationService,
                                          ObjectMapper mapper) implements Function<InputStream, String> {

    @Override
    public String apply(InputStream inputStream) {
        var cred = revocationService.createStatusListCredential();
        try {
            return mapper.writeValueAsString(cred);
        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }
}

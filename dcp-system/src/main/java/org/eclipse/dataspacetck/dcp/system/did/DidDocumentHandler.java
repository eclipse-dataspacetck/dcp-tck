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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.function.Function;

/**
 * Serves DID documents.
 */
public class DidDocumentHandler implements Function<InputStream, String> {
    private DidService didService;
    private ObjectMapper mapper;

    public DidDocumentHandler(DidService didService, ObjectMapper mapper) {
        this.didService = didService;
        this.mapper = mapper;
    }

    @Override
    public String apply(InputStream inputStream) {
        try {
            var result = didService.resolveDidDocument();
            if (result.failed()) {
                throw new RuntimeException("Error resolving DID document: " + result.getFailure());
            }
            return mapper.writeValueAsString(result.getContent());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

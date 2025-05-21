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

package org.eclipse.dataspacetck.dcp.system.handler;

import org.eclipse.dataspacetck.core.api.system.HandlerResponse;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

public class SchemaProvider extends AbstractProtocolHandler {

    public SchemaProvider() {
        super("/credential-schemas/membership-credential-schema.json");
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {
        var schemaJson = schema.getSchemaNode().toString();
        return new HandlerResponse(200, schemaJson, Map.of(
                "Content-Type", "application/schema+json"
        ));
    }

}

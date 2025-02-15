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

package org.eclipse.dataspacetck.dcp.system.handler;

import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import org.eclipse.dataspacetck.core.api.system.ProtocolHandler;

import static com.networknt.schema.SpecVersion.VersionFlag.V202012;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.DCP_NAMESPACE;

/**
 * Base handler functionality.
 */
public abstract class AbstractProtocolHandler implements ProtocolHandler {
    protected static final String PRESENTATION_EXCHANGE_PREFIX = "https://identity.foundation/";
    protected static final String CLASSPATH_SCHEMA = "classpath:/";

    protected JsonSchema schema;

    public AbstractProtocolHandler(String schemaFile) {
        var schemaFactory = JsonSchemaFactory.getInstance(V202012, builder ->
                builder.schemaMappers(schemaMappers ->
                        schemaMappers.mapPrefix(DCP_NAMESPACE + "/", CLASSPATH_SCHEMA)
                                .mapPrefix(PRESENTATION_EXCHANGE_PREFIX, CLASSPATH_SCHEMA))
        );

        schema = schemaFactory.getSchema(SchemaLocation.of(DCP_NAMESPACE + schemaFile));
    }
}

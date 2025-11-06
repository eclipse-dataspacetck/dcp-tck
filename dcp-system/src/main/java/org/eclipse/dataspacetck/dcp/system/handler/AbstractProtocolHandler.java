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

import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialects;
import org.eclipse.dataspacetck.core.api.system.ProtocolHandler;

import java.util.List;

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.DCP_NAMESPACE;

/**
 * Base handler functionality.
 */
public abstract class AbstractProtocolHandler implements ProtocolHandler {
    protected static final String PRESENTATION_EXCHANGE_PREFIX = "https://identity.foundation/";
    protected static final String CLASSPATH_SCHEMA = "classpath:/";

    protected Schema schema;

    public AbstractProtocolHandler(String schemaFile) {
        var dialects = List.of(Dialects.getDraft201909(), Dialects.getDraft7());
        var schemaFactory = SchemaRegistry.withDialects(dialects, builder ->
                builder.schemaIdResolvers(schemaIdResolvers ->
                        schemaIdResolvers.mapPrefix(DCP_NAMESPACE + "/", CLASSPATH_SCHEMA)
                                .mapPrefix(PRESENTATION_EXCHANGE_PREFIX, CLASSPATH_SCHEMA))
        );

        schema = schemaFactory.getSchema(SchemaLocation.of(DCP_NAMESPACE + schemaFile));
    }
}

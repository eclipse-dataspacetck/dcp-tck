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

package org.eclipse.dataspacetck.dcp.system.message;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CONTEXT;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.DCP_CONTEXT;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;

/**
 * Builds a DCP message.
 */
public class DcpMessageBuilder {
    private Map<String, Object> message;

    public static DcpMessageBuilder newInstance() {
        return new DcpMessageBuilder();
    }

    public DcpMessageBuilder type(String type) {
        message.put(TYPE, type);
        return this;
    }

    public DcpMessageBuilder property(String key, Object value) {
        message.put(key, value);
        return this;
    }

    public Map<String, Object> build() {
        requireNonNull(message.get(TYPE), "type");
        return message;
    }

    private DcpMessageBuilder() {
        message = new LinkedHashMap<>();
        var context = new ArrayList<String>();
        context.add(DCP_CONTEXT);
        message.put(CONTEXT, context);
    }
}

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

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CONTEXT;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.DCP_NAMESPACE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TYPE;

/**
 * Utility methods for creating DCP messages.
 */
public class MessageFunctions {

    public static Map<String, Object> baseMessage(String type) {
        var message = new LinkedHashMap<String, Object>();
        var context = new ArrayList<String>();
        context.add(DCP_NAMESPACE);
        message.put(CONTEXT, context);
        message.put(TYPE, type);
        return message;
    }

    private MessageFunctions() {
    }
}

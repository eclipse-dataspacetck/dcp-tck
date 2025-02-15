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

package org.eclipse.dataspacetck.dcp.system.cs;

import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE_ALIAS;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

public class SecureTokenServerImpl implements SecureTokenServer {
    private Map<String, String> readTokens = new ConcurrentHashMap<>();
    private Map<String, String> writeAuthorizations = new ConcurrentHashMap<>();

    @Override
    public Result<String> obtainReadToken(String bearerDid, List<String> scopes) {
        var types = transformScopes(scopes);
        var token = randomUUID() + "::" + bearerDid + "::" + types;
        readTokens.put(token, token);
        return success(token);
    }

    @Override
    public Result<List<String>> validateReadToken(String bearerDid, String token) {
        if (readTokens.remove(token) == null) {
            return failure("Token not valid");
        }
        var parts = token.split("::");
        if (parts.length != 3) {
            return failure("Invalid token format");
        }
        if (!parts[1].equals(bearerDid)) {
            return failure("Token binding not valid");
        }
        return success(Arrays.asList(parts[2].split(",")));
    }

    @Override
    public void authorizeWrite(String bearerDid, String correlationId, List<String> scopes) {
        var types = transformScopes(scopes);
        writeAuthorizations.put(bearerDid + "::" + correlationId, types);
    }

    @Override
    public Result<List<String>> validateWrite(String bearerDid, String correlationId) {
        var entry = writeAuthorizations.remove(bearerDid + "::" + correlationId);
        return entry == null ? failure("Not authorized") : success(asList(entry.split(",")));
    }

    @NotNull
    private String transformScopes(List<String> scopes) {
        return scopes.stream().map(scope->{
            if (!scope.startsWith(SCOPE_TYPE_ALIAS)) {
                throw new IllegalArgumentException("Invalid scope: " + scope);
            }
            return scope.substring(SCOPE_TYPE_ALIAS.length());
        }).collect(Collectors.joining(","));
    }

}

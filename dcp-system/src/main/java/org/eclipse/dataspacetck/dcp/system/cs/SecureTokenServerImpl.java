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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.system.sts.SecureTokenServer;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_PREFIX;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE_ALIAS;
import static org.eclipse.dataspacetck.dcp.system.service.Result.failure;
import static org.eclipse.dataspacetck.dcp.system.service.Result.success;

public class SecureTokenServerImpl implements SecureTokenServer {
    private final Map<String, String> readTokens = new ConcurrentHashMap<>();
    private final Map<String, String> writeAuthorizations = new ConcurrentHashMap<>();
    private final String stsUrl;
    private final String stsClientId;
    private final String stsClientSecret;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SecureTokenServerImpl(ServiceConfiguration configuration) {
        this.stsUrl = configuration.getPropertyAsString(TCK_PREFIX + ".sts.url", null);
        this.stsClientId = configuration.getPropertyAsString(TCK_PREFIX + ".sts.client.id", null);
        this.stsClientSecret = configuration.getPropertyAsString(TCK_PREFIX + ".sts.client.secret", null);
    }

    @Override
    public Result<String> obtainReadToken(String bearerDid, List<String> scopes) {

        if (stsUrl == null) { // use embedded holder STS
            var types = transformScopes(scopes);
            var token = randomUUID() + "::" + bearerDid + "::" + types;
            readTokens.put(token, token);
            return success(token);
        } else { // use external STS
            var scopeString = String.join(" ", scopes);
            if (stsClientId == null || stsClientSecret == null) {
                return failure("When overriding the STS URL, client ID and secret must be provided");
            }
            return requestRemoteAccessToken(stsUrl, stsClientId, stsClientSecret, bearerDid, scopeString);
        }
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
        return scopes.stream().map(scope -> {
            if (!scope.startsWith(SCOPE_TYPE_ALIAS)) {
                throw new IllegalArgumentException("Invalid scope: " + scope);
            }
            return scope.substring(SCOPE_TYPE_ALIAS.length());
        }).collect(Collectors.joining(","));
    }

    /**
     * Request a token from a remote ("real") STS
     *
     * @param stsUrl          the URL of the STS
     * @param stsClientId     the client ID for the token request
     * @param stsClientSecret the client secret for the token request
     * @param audience        the desired 'aud' claim of the token
     * @param scopes          a space-separated list of scopes to be included in the token
     * @return the access token (i.e. the "inner" token) returned from the STS
     */
    private Result<String> requestRemoteAccessToken(String stsUrl, String stsClientId, String stsClientSecret, String audience, String scopes) {
        var rq = new Request.Builder()
                .url(stsUrl + "/token")
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .post(new FormBody.Builder()
                        .add("grant_type", "client_credentials")
                        .add("client_id", stsClientId)
                        .add("client_secret", stsClientSecret)
                        .add("audience", audience)
                        .add("bearer_access_scope", scopes)
                        .build())
                .build();

        var client = new OkHttpClient();
        try (var response = client.newCall(rq).execute()) {
            if (response.isSuccessful()) {
                var body = response.body();
                if (body != null) {
                    var token = objectMapper.readValue(body.string(), Map.class).get("access_token").toString();
                    var tokenClaim = SignedJWT.parse(token).getJWTClaimsSet().getClaim("token").toString();
                    return success(tokenClaim);
                }
            }
            return failure("Request failed with HTTP code " + response.code());
        } catch (IOException e) {
            return failure("Error requesting token: " + e.getMessage());
        } catch (ParseException e) {
            return failure("Failed to parse token: " + e.getMessage());
        }
    }

}

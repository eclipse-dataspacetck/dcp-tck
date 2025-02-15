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

package org.eclipse.dataspacetck.dcp.verification.fixtures;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.message.DcpConstants;
import org.eclipse.dataspacetck.dcp.system.model.did.VerificationMethod;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VC;

/**
 * Testing functions.
 */
public class TestFixtures {

    /**
     * Executes the request and applies the given verification.
     */
    public static void executeRequest(Request request, Consumer<Response> verification) {
        var client = new OkHttpClient();
        var call = client.newCall(request);
        try (var response = call.execute()) {
            verification.accept(response);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, Object> createPresentationDefinition(String credentialType) {
        var fields = new HashMap<String, Object>();
        fields.put("path", List.of("$.type"));
        fields.put("filter", Map.of("type", "string", "pattern", credentialType));

        var descriptor = new HashMap<String, Object>();
        descriptor.put(ID, "credential");
        descriptor.put("format", "vcdm11_jwt");
        descriptor.put("constraints", Map.of("fields", fields));
        var map = new HashMap<String, Object>();
        map.put(ID, randomUUID().toString());
        map.put("input_descriptors", List.of(descriptor));
        return map;
    }

    public static void assert4XXXCode(Response response) {
        assertThat(response.isSuccessful()).isFalse();
        assertThat(response.code() >= 400).isTrue();
        assertThat(response.code() <= 500).isTrue();
    }

    public static VerificationMethod resolveKeyMaterial(String kid) {
        var kidTokens = kid.split("#");
        if (kidTokens.length != 2) {
            throw new AssertionError("Key material must have two parts: " + kid);
        }
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(kidTokens[0]);
        return document.getVerificationMethod(kidTokens[1]);
    }

    public static List<String> parseAndVerifyPresentation(List<String> presentations, String audience) {
        return presentations.stream().flatMap(vp -> {
            try {
                var parsedVp = parseAndVerifyJwt(vp);

                var claims = parsedVp.getJWTClaimsSet();

                var aud = claims.getAudience();
                assertThat(aud).isNotNull();
                assertThat(aud).containsOnly(audience);

                @SuppressWarnings("unchecked")
                var serializedVcs = (List<String>) parsedVp.getJWTClaimsSet().getClaim(VC);
                return parseAndVerifyCredentials(serializedVcs);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }

        }).toList();
    }

    public static Stream<String> parseAndVerifyCredentials(List<String> credentialJwts) {
        return credentialJwts.stream().flatMap(jwt -> {
            try {
                var parsedVc = parseAndVerifyJwt(jwt);
                @SuppressWarnings("unchecked")
                Map<String, Object> vc = (Map<String, Object>) parsedVc.getJWTClaimsSet().getClaim(VC);
                //noinspection unchecked
                return ((List<String>) vc.get(DcpConstants.TYPE)).stream();
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        });
    }

    @NotNull
    private static SignedJWT parseAndVerifyJwt(String jwt) {
        try {
            var parsedVc = SignedJWT.parse(jwt);
            var kid = parsedVc.getHeader().getKeyID();
            var material = resolveKeyMaterial(kid);
            var jwk = JWK.parse(material.getPublicKeyJwk());
            var vcVerifier = createVerifier(jwk.toECKey().toPublicKey());

            assertThat(parsedVc.verify(vcVerifier)).isTrue();

            return parsedVc;
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}

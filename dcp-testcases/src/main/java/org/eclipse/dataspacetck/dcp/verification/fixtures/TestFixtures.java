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

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VC;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VERIFIABLE_CREDENTIAL_CLAIM;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VP;

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

    /**
     * Executes the request and applies the given verification, returning the result of the verification function
     */
    public static <T> T executeRequestAndGet(Request request, Function<Response, T> verification) {
        var client = new OkHttpClient();
        var call = client.newCall(request);
        try (var response = call.execute()) {
            return verification.apply(response);
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

    public static void assert4xxCode(Response response) {
        assertThat(response.code())
                .withFailMessage("Expected a 4xx client error HTTP code but got %s".formatted(response.code()))
                .isBetween(400, 500);
        assertThat(response.isSuccessful()).isFalse();
    }

    public static VerificationMethod resolveKeyMaterial(String kid) {
        var kidTokens = kid.split("#");
        if (kidTokens.length != 2) {
            throw new AssertionError("Key material must have two parts: [documentId]#[keyId], but was: " + kid);
        }
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(kidTokens[0]);
        // IDs can be relative (e.g. "#key-1") or absolute (e.g. "did:example:123#key-1").
        // if relative, they are resolved against the document ID. To make resolution easier, and because we have already
        // parsed anyway, we pass just the relative ID
        var vm = document.getVerificationMethod("#" + kidTokens[1]);
        if (vm.failed()) {
            throw new AssertionError("Key material could not be resolved: " + vm.getFailure());
        }
        return vm.getContent();
    }

    /**
     * Resolves the credential service endpoint from its DID.
     */
    public static String resolveCredentialServiceEndpoint(String holderDid) {
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(holderDid);
        return document.getServiceEntry(CREDENTIAL_SERVICE_TYPE).serviceEndpoint();
    }

    /**
     * Resolves the issuer service endpoint from its DID.
     */
    public static String resolveIssuerServiceEndpoint(String holderDid) {
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(holderDid);
        return document.getServiceEntry(ISSUER_SERVICE_TYPE).serviceEndpoint();
    }

    @SuppressWarnings("unchecked")
    public static List<String> parseAndVerifyPresentation(List<String> presentations, String audience) {
        return presentations.stream().flatMap(vp -> {
            try {
                var parsedVp = parseAndVerifyJwt(vp);

                var claims = parsedVp.getJWTClaimsSet();

                var aud = claims.getAudience();
                assertThat(aud).isNotNull();
                assertThat(aud).containsOnly(audience);

                var presentationList = objectOrMap(parsedVp.getJWTClaimsSet().getClaim(VP));

                // extract and flatmap all credentials from all presentations
                var credentialJwts = presentationList.stream().map(pres -> pres.get(VERIFIABLE_CREDENTIAL_CLAIM))
                                             .map(o -> (List<String>) o)
                                             .flatMap(Collection::stream)
                                             .toList();

                return parseAndVerifyCredentials(credentialJwts);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }

        }).toList();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> objectOrMap(Object vpClaim) {
        if (vpClaim instanceof Map) {
            return List.of((Map<String, Object>) vpClaim);
        } else if (vpClaim instanceof Collection<?>) {
            return ((List<Map<String, Object>>) vpClaim);
        }
        throw new IllegalArgumentException("Unsupported type: " + vpClaim.getClass().getName());
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

    public static void assert2xxCode(Response response) {
        assertThat(response.code()).isBetween(200, 300);
        assertThat(response.isSuccessful()).isTrue();
    }

    public static <T> T bodyAs(Response response, Class<T> type, ObjectMapper objectMapper) {
        try {
            return objectMapper.readValue(response.body().byteStream(), type);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

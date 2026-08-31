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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.message.DcpConstants;
import org.eclipse.dataspacetck.dcp.system.model.did.DidDocument;
import org.eclipse.dataspacetck.dcp.system.model.did.VerificationMethod;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.crypto.Keys.createVerifier;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.AUTHORIZATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.ISSUER_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.JSON_CONTENT_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
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
        var kidTokens = splitKid(kid);
        var document = resolveDocument(kidTokens[0]);
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
     * Derives a syntactically valid but unresolvable {@code did:web} from an existing one by replacing its last path
     * segment. Used to verify that a receiver rejects tokens whose {@code sub} DID cannot be resolved.
     */
    public static String unresolvableDid(String did) {
        var lastSegment = did.lastIndexOf(':');
        if (lastSegment < 0) {
            throw new IllegalArgumentException("Not a path-based DID: " + did);
        }
        return did.substring(0, lastSegment + 1) + "unresolvable-" + randomUUID();
    }

    /**
     * Resolves a DID document, failing the test if it cannot be resolved.
     */
    public static DidDocument resolveDocument(String did) {
        return new DidClient(false).resolveDocument(did);
    }

    /**
     * Asserts that the key referenced by {@code kid} is listed under the given verification relationship in its DID
     * document. DCP requires presentations to be signed with an {@code authentication} key and self-issued tokens with
     * a {@code capabilityInvocation} key, so merely resolving the key is not sufficient.
     *
     * @param kid          the key id, in {@code [documentId]#[keyId]} form.
     * @param relationship one of {@code authentication}, {@code assertionMethod} or {@code capabilityInvocation}.
     */
    public static void assertVerificationRelationship(String kid, String relationship) {
        var kidTokens = splitKid(kid);
        var document = resolveDocument(kidTokens[0]);
        var references = switch (relationship) {
            case "authentication" -> document.getAuthentication();
            case "assertionMethod" -> document.getAssertionMethod();
            case "capabilityInvocation" -> document.getCapabilityInvocation();
            default -> throw new IllegalArgumentException("Unknown verification relationship: " + relationship);
        };

        // references may be relative ("#key-1") or absolute ("did:example:123#key-1")
        var relative = "#" + kidTokens[1];
        assertThat(references)
                .withFailMessage(() -> "Key '%s' does not carry the '%s' verification relationship, found: %s"
                        .formatted(kid, relationship, references))
                .anyMatch(ref -> ref.equals(kid) || ref.equals(relative));
    }

    private static String[] splitKid(String kid) {
        var kidTokens = kid.split("#");
        if (kidTokens.length != 2) {
            throw new AssertionError("Key material must have two parts: [documentId]#[keyId], but was: " + kid);
        }
        return kidTokens;
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

    public static List<String> parseAndVerifyPresentation(List<String> presentations, String audience) {
        return parseAndVerifyPresentation(presentations, audience, null);
    }

    /**
     * Parses the returned presentations, verifies their proofs and returns the types of all contained credentials.
     *
     * @param presentations  the raw presentation JWTs.
     * @param audience       the DID the presentations must be addressed to.
     * @param expectedHolder the DID that must have issued and be named as holder of each presentation. If null, holder
     *                       binding is not asserted.
     */
    @SuppressWarnings("unchecked")
    public static List<String> parseAndVerifyPresentation(List<String> presentations, String audience, String expectedHolder) {
        return presentations.stream().flatMap(vp -> {
            try {
                var parsedVp = parseAndVerifyJwt(vp);

                var claims = parsedVp.getJWTClaimsSet();

                var aud = claims.getAudience();
                assertThat(aud).isNotNull();
                assertThat(aud).containsOnly(audience);

                if (expectedHolder != null) {
                    // DCP 5.4.3: the presentation must be bound to the credential service's DID and signed with a key
                    // carrying the 'authentication' verification relationship
                    assertThat(claims.getIssuer())
                            .withFailMessage("Expected the presentation to be issued by '%s' but was '%s'", expectedHolder, claims.getIssuer())
                            .isEqualTo(expectedHolder);
                    assertVerificationRelationship(parsedVp.getHeader().getKeyID(), "authentication");
                }

                var presentationList = objectOrMap(parsedVp.getJWTClaimsSet().getClaim(VP));

                if (expectedHolder != null) {
                    presentationList.stream()
                            .map(pres -> pres.get("holder"))
                            .filter(java.util.Objects::nonNull)
                            .forEach(holder -> assertThat(holder)
                                    .withFailMessage("Expected presentation holder to be '%s' but was '%s'", expectedHolder, holder)
                                    .isEqualTo(expectedHolder));
                }

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

    /**
     * Creates a signed self-issued ID token per the DCP spec, optionally carrying an access token in the
     * {@code token} claim.
     */
    public static String createIdToken(KeyService keyService, String issuerDid, String audienceDid, String accessToken) {
        var builder = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .subject(issuerDid)
                .audience(audienceDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)));
        if (accessToken != null) {
            builder.claim(TOKEN, accessToken);
        }
        return keyService.sign(emptyMap(), builder.build());
    }

    /**
     * Creates a DCP presentation query request against the credential service resolved from the given DID.
     */
    public static Request createPresentationRequest(String credentialServiceDid, String idToken,
                                                    Map<String, Object> message, ObjectMapper mapper) {
        var endpoint = resolveCredentialServiceEndpoint(credentialServiceDid);
        try {
            return new Request.Builder()
                    .url(endpoint + PRESENTATION_QUERY_PATH)
                    .header(AUTHORIZATION, "Bearer " + idToken)
                    .post(RequestBody.create(mapper.writeValueAsString(message), MediaType.parse(JSON_CONTENT_TYPE)))
                    .build();
        } catch (JacksonException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Asserts the envelope of a {@code CredentialMessage} received on the TCK's Storage API: the required properties
     * are present and the pids correlate with the request that triggered the delivery.
     *
     * @param message           the received message.
     * @param expectedHolderPid the {@code holderPid} the corresponding request was made with.
     * @param expectedStatus    the expected {@code status}, e.g. {@code ISSUED}.
     */
    public static void assertCredentialMessageEnvelope(Map<String, Object> message, String expectedHolderPid, String expectedStatus) {
        assertThat(message).containsKey(DcpConstants.CONTEXT);
        assertThat(message.get(DcpConstants.TYPE)).isEqualTo(DcpConstants.CREDENTIAL_MESSAGE_TYPE);
        assertThat(message.get("holderPid"))
                .withFailMessage("Expected the delivery to correlate with holderPid '%s' but was '%s'",
                        expectedHolderPid, message.get("holderPid"))
                .isEqualTo(expectedHolderPid);
        assertThat(message.get("issuerPid"))
                .withFailMessage("Expected the delivery to carry a non-null issuerPid")
                .isNotNull();
        assertThat(message.get("status")).isEqualTo(expectedStatus);
    }

    /**
     * Parses a self-issued token and asserts the DCP 4.3 claims required of a message sent by {@code expectedIssuer}
     * to {@code expectedAudience}. Returns the parsed claims so callers can assert further, e.g. on the
     * {@code token} claim.
     */
    public static JWTClaimsSet parseAndVerifySelfIssuedToken(String jwt, String expectedIssuer, String expectedAudience) {
        try {
            var parsed = parseAndVerifyJwt(jwt);
            var claims = parsed.getJWTClaimsSet();
            assertThat(claims.getIssuer()).isEqualTo(expectedIssuer);
            assertThat(claims.getSubject()).isEqualTo(expectedIssuer);
            assertThat(claims.getAudience()).containsOnly(expectedAudience);
            return claims;
        } catch (ParseException e) {
            throw new AssertionError(e);
        }
    }

    public static void assert2xxCode(Response response) {
        assertThat(response.code()).isBetween(200, 300);
        assertThat(response.isSuccessful()).isTrue();
    }

    public static <T> T bodyAs(Response response, Class<T> type, ObjectMapper objectMapper) {
        try {
            return objectMapper.readValue(response.body().byteStream(), type);
        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }

}

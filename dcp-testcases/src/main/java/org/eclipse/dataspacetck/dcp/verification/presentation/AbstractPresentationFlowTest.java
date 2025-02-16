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

package org.eclipse.dataspacetck.dcp.verification.presentation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.ValidationMessage;
import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderDid;
import org.eclipse.dataspacetck.dcp.system.annotation.PresentationFlow;
import org.eclipse.dataspacetck.dcp.system.annotation.Verifier;
import org.eclipse.dataspacetck.dcp.system.annotation.VerifierDid;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.networknt.schema.SpecVersion.VersionFlag.V202012;
import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.DCP_NAMESPACE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_QUERY_PATH;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.parseAndVerifyPresentation;

/**
 * Base test class.
 */
@PresentationFlow
@ExtendWith(SystemBootstrapExtension.class)
public class AbstractPresentationFlowTest {
    protected static final String AUTHORIZATION = "Authorization";
    protected static final String JSON_CONTENT_TYPE = "application/json";
    protected static final String PRESENTATION_EXCHANGE_PREFIX = "https://identity.foundation/";
    protected static final String CLASSPATH_SCHEMA = "classpath:/";

    protected static JsonSchema responseSchema;

    @Inject
    @VerifierDid
    protected String verifierDid;

    @Inject
    @HolderDid
    protected String holderDid;

    @Inject
    @Verifier
    protected KeyService verifierKeyService;

    protected ObjectMapper mapper = new ObjectMapper();

    @BeforeAll
    protected static void setUp() {
        var schemaFactory = JsonSchemaFactory.getInstance(V202012, builder ->
                builder.schemaMappers(schemaMappers ->
                        schemaMappers.mapPrefix(DCP_NAMESPACE + "/", CLASSPATH_SCHEMA)
                                .mapPrefix(PRESENTATION_EXCHANGE_PREFIX, CLASSPATH_SCHEMA))
        );

        responseSchema = schemaFactory.getSchema(SchemaLocation.of(DCP_NAMESPACE + "/presentation/presentation-response-message-schema.json"));
    }

    /**
     * Creates a DCP presentation request.
     */
    protected Request createPresentationRequest(String authToken, Map<String, Object> message) {
        var endpoint = resolveCredentialServiceEndpoint();
        try {
            return new Request.Builder()
                    .url(endpoint + PRESENTATION_QUERY_PATH)
                    .header(AUTHORIZATION, "Bearer " + createIdToken(authToken))
                    .post(RequestBody.create(mapper.writeValueAsString(message), MediaType.parse(JSON_CONTENT_TYPE)))
                    .build();
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Creates a signed self-issued ID token per the DCP spec.
     */
    protected String createIdToken(String authToken) {
        var claimSet = new JWTClaimsSet.Builder()
                .issuer(verifierDid)
                .audience(holderDid)
                .subject(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();
        return verifierKeyService.sign(emptyMap(), claimSet);
    }

    /**
     * Resolves the credential service endpoint from its DID.
     */
    protected String resolveCredentialServiceEndpoint() {
        var didClient = new DidClient(false);
        var document = didClient.resolveDocument(holderDid);
        return document.getServiceEntry(CREDENTIAL_SERVICE_TYPE).getServiceEndpoint();
    }

    public void verifyCredentials(Response response, String... expectedTypes) {
        assertThat(response.isSuccessful())
                .withFailMessage("Request failed: " + response.code()).isTrue();

        try {
            assert response.body() != null;
            var responseMessage = mapper.readValue(response.body().bytes(), Map.class);

            var schemaResult = responseSchema.validate(mapper.convertValue(responseMessage, JsonNode.class));
            assertThat(schemaResult).withFailMessage(() -> "Schema validation failed: " + schemaResult.stream()
                    .map(ValidationMessage::getMessage).collect(Collectors.joining())).isEmpty();

            @SuppressWarnings("unchecked")
            var presentations = (List<String>) responseMessage.get(PRESENTATION);
            var credentialTypes = parseAndVerifyPresentation(presentations, verifierDid);

            assertThat(credentialTypes).containsOnly(expectedTypes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }


}

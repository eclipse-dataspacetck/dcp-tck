package org.eclipse.dataspacetck.dcp.verification.presentation.verifier;

import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.dcp.system.annotation.AuthToken;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.IssueCredentials;
import org.eclipse.dataspacetck.dcp.system.annotation.RoleType;
import org.eclipse.dataspacetck.dcp.system.annotation.TriggerEndpoint;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.cs.Delegates;
import org.eclipse.dataspacetck.dcp.system.did.DidClient;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.generation.JwtPresentationGenerator;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat;
import org.eclipse.dataspacetck.dcp.system.model.vc.MetadataReference;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.system.revocation.CredentialRevocationService;
import org.eclipse.dataspacetck.dcp.system.service.Result;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_SERVICE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.PRESENTATION_RESPONSE_MESSAGE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_SCOPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;

/**
 * This test asserts that the Verifier behaves correctly, according to DCP. To kick off the Presentation Flow, a configurable REST
 * request is sent that carries the initial ID token in the Authorization header.
 * <p>
 * For Verifiers that also implement DSP, the /catalog endpoint could be used.
 */
public class PresentationFlowSection5Test extends AbstractVerifierPresentationFlowTest {
    @Inject
    @TriggerEndpoint
    private String triggerEndpoint;

    @DisplayName("Verifier should resolve the DID from the prover's ID token")
    @MandatoryTest
    @IssueCredentials(MEMBERSHIP_SCOPE)
    void presentationResponse_endpointDiscovery() {
        var didClient = new DidClient(false);
        var didDocument = didClient.resolveDocument(verifierDid);
        assertThat(didDocument).isNotNull();
        assertThat(didDocument.getServiceEntry(CREDENTIAL_SERVICE_TYPE).serviceEndpoint()).isNotNull();
    }

    @DisplayName("5.1 Verifier should accept a valid PresentationResponseMessage")
    @MandatoryTest
    @IssueCredentials({MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE})
    void verifier_05_01_presentationResponse_success(@AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var triggerMessage = createTriggerMessage();

        var rq = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), triggerMessage);
        executeRequest(rq, TestFixtures::assert2xxCode);
    }


    @DisplayName("5.4.2.1 Verifier should reject a presentation response message that contains a different credential than requested")
    @MandatoryTest
    @IssueCredentials({MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE})
    void verifier_05_04_02_01_presentationResponse_tooFewCredentials(@AuthToken("org.eclipse.dspace.dcp.vc.type:SomeOtherCredential:read") String authToken) {
        executeRequest(createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage()), TestFixtures::assert4xxCode);
    }

    @DisplayName("5.4.2.2 Verifier should accept a presentation response message that contains more credentials than requested")
    @MandatoryTest
    @IssueCredentials({MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE})
    void verifier_05_04_02_02_presentationResponse_tooManyCredentials(@AuthToken({MEMBERSHIP_SCOPE, SENSITIVE_DATA_SCOPE}) String authToken) {
        executeRequest(createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage()), TestFixtures::assert2xxCode);
    }



    @DisplayName("5.4.2.3 Verifier should reject an empty 'presentation' array")
    @MandatoryTest
    void verifier_05_04_02_03_presentationResponse_emptyPresentations(@AuthToken(SENSITIVE_DATA_SCOPE) String authToken,
                                                 @Holder CredentialService holderCredentialService) {
        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());

        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                return Result.success(DcpMessageBuilder.newInstance()
                        .type(PRESENTATION_RESPONSE_MESSAGE)
                        .property(PRESENTATION, List.of())
                        .build());
            }
        });
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @DisplayName("5.4.2.4 Verifier should reject an a presentation where a requested credential is missing")
    @MandatoryTest
    void verifier_05_04_02_04_presentationResponse_emptyCredentials(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                               @Holder CredentialService holderCredentialService) {
        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());

        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                return Result.success(createPresentation());
            }
        });
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("5.4.3 Verifier should reject Presentations where the holder does not match the credentialSubject.id")
    void verifier_05_04_03_presentationResponse_holderNotEqualSubjectId(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                      @Did(RoleType.THIRD_PARTY) String thirdPartyDid,
                                                      @Holder CredentialService holderCredentialService) {

        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());

        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                // create credential - subject-id is not equal to presentation holder
                var cred = createCredential()
                        .credentialSubject(Map.of("id", thirdPartyDid, "foo", "bar"))
                        .build();

                return Result.success(createPresentation(cred));
            }
        });
        executeRequest(request, TestFixtures::assert4xxCode);
    }



    @MandatoryTest
    @DisplayName("5.4.3.7 Verifier should reject an expired credential")
    void verifier_05_04_03_07_presentationResponse_expiredCredential(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                @TriggerEndpoint String triggerEndpoint,
                                                @Holder CredentialService holderCredentialService) {
        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                var cred = createCredential()
                        .expirationDate(Instant.now().minusSeconds(100).toString())
                        .build();
                return Result.success(createPresentation(cred));
            }
        });

        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("5.4.3.6 Verifier should reject Presentations where at least 1 credential is revoked/suspended")
    void verifier_05_04_03_06_presentationResponse_credentialRevoked(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                                     @TriggerEndpoint String triggerEndpoint,
                                                                     @Holder CredentialService holderCredentialService,
                                                                     CredentialRevocationService credentialRevocationService) {

        var index = 1;
        credentialRevocationService.setRevoked(index);

        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                // create credential - subject-id is not equal to presentation holder
                var cred = createCredential()
                        .credentialStatus(MetadataReference.Builder.newInstance()
                                .id(UUID.randomUUID().toString())
                                .type("BitstringStatusListEntry")
                                .setExtensibleProperty("statusPurpose", "revocation")
                                .setExtensibleProperty("statusListIndex", String.valueOf(index))
                                .setExtensibleProperty("statusListCredential", "%s/statuslist/%s".formatted(credentialRevocationService.getAddress(), credentialRevocationService.getCredentialId()))
                                .build())
                        .build();
                return Result.success(createPresentation(cred));
            }
        });

        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    @MandatoryTest
    @DisplayName("5.4.3.6 Verifier should reject a credential that is not yet valid")
    void verifier_05_04_03_06_presentationResponse_notYetValidCredential(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                    @TriggerEndpoint String triggerEndpoint,
                                                    @Holder CredentialService holderCredentialService) {
        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                var cred = createCredential()
                        .issuanceDate(Instant.now().plusSeconds(3600).toString()) //in future
                        .build();
                return Result.success(createPresentation(cred));
            }
        });

        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());
        executeRequest(request, TestFixtures::assert4xxCode);
    }


    @MandatoryTest
    @DisplayName("X.X Verifier should reject Presentations where at least 1 credential schema is violated")
    void verifier_x_x_presentationResponse_invalidCredentialSchema(@AuthToken(MEMBERSHIP_SCOPE) String authToken,
                                                      @TriggerEndpoint String triggerEndpoint,
                                                      @Holder CredentialService holderCredentialService,
                                                      CredentialRevocationService srv) {
        holderCredentialService.withDelegate(new PresentationProvider() {
            @Override
            public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
                var cred = createCredential()
                        .credentialSubject(Map.of("id", holderDid, "baz", "quazz")) // "foo" property is missing -> will trigger schema violation
                        .credentialSchema(MetadataReference.Builder.newInstance()
                                .type("JsonSchemaValidator2018")
                                .id("%s/schema/membership-schema.json".formatted(srv.getAddress()))
                                .build())
                        .build();
                return Result.success(createPresentation(cred));
            }
        });

        var request = createRequest(triggerEndpoint, "Bearer " + createIdToken(authToken), createTriggerMessage());
        executeRequest(request, TestFixtures::assert4xxCode);
    }

    // utility class that contains helpers for creating credentials and presentations
    private abstract class PresentationProvider implements Delegates.PresentationQuery {

        VerifiableCredential.Builder createCredential() {
            return VerifiableCredential.Builder.newInstance()
                    .id(randomUUID().toString())
                    .issuanceDate(Instant.now().toString())
                    .issuer(issuerDid)
                    .type(List.of(MEMBERSHIP_CREDENTIAL_TYPE))
                    // credential subject cannot be empty
                    .credentialSubject(Map.of("id", holderDid, "foo", "bar"));
        }

        Map<String, Object> createPresentation(VerifiableCredential... credentials) {

            var containers = Stream.of(credentials).map(cred -> {
                var rawJwt = new JwtCredentialGenerator(issuerDid, issuerKeyService).generateCredential(cred);
                return new VcContainer(rawJwt.getContent(), cred, CredentialFormat.VC1_0_JWT);
            }).toList();

            // error: should be 'holderDid' instead!
            var rawPres = new JwtPresentationGenerator(holderDid, holderKeyService)
                    .generatePresentation(verifierDid, holderDid, containers);
            return DcpMessageBuilder.newInstance()
                    .type(PRESENTATION_RESPONSE_MESSAGE)
                    .property(PRESENTATION, List.of(rawPres.getContent()))
                    .build();
        }

    }
}


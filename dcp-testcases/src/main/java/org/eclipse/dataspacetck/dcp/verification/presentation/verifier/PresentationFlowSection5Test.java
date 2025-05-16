package org.eclipse.dataspacetck.dcp.verification.presentation.verifier;

import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.api.system.MandatoryTest;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.AuthToken;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.IssueCredentials;
import org.eclipse.dataspacetck.dcp.system.annotation.PresentationFlow;
import org.eclipse.dataspacetck.dcp.system.annotation.TriggerEndpoint;
import org.eclipse.dataspacetck.dcp.system.annotation.Verifier;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Date;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.VERIFIER;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_SCOPE;
import static org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures.executeRequest;

/**
 * This test asserts that the Verifier behaves correctly, according to DCP. To kick off the Presentation Flow, a configurable REST
 * request is sent, that carries the initial ID token in the Authorization header.
 * <p>
 * For Verifiers, that also implement DSP, the /catalog endpoint could be used.
 */
@PresentationFlow
@ExtendWith(SystemBootstrapExtension.class)
public class PresentationFlowSection5Test {

    @Inject
    @Holder
    private KeyService holderKeyService;

    @Inject
    @Did(VERIFIER)
    protected String verifierDid;

    @Inject
    @Did(HOLDER)
    protected String holderDid;

    @DisplayName("Verifier should resolve the DID from the prover's ID token")
    @MandatoryTest
    @IssueCredentials(MEMBERSHIP_SCOPE)
    void presentationResponse_verifyServiceResolution(@TriggerEndpoint String triggerEndpoint, @AuthToken(MEMBERSHIP_SCOPE) String authToken) {
        var triggerMessage = """
                {
                    "@type":  "https://w3id.org/dspace/2024/1/CatalogRequestMessage",
                    "https://w3id.org/dspace/v0.8/filter": {}
                }
                """;

        var rq = new Request.Builder()
                .url(triggerEndpoint)
                .header("Authorization", createIdToken(authToken))
                .post(RequestBody.create(triggerMessage, MediaType.parse("application/json")))
                .build();
        executeRequest(rq, TestFixtures::assert2xxCode);
    }

    private String createIdToken(String authToken) {

        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .audience(verifierDid)
                .subject(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)))
                .claim(TOKEN, authToken)
                .build();

        return holderKeyService.sign(emptyMap(), claimSet);
    }

    @DisplayName("Verifier should accept a valid PresentationResponseMessage")
    @MandatoryTest
    void presentationResponse_success() {

    }

    @DisplayName("Verifier should reject a message that contains fewer credentials as requested")
    @MandatoryTest
    void presentationResponse_tooFewCredentials() {

    }

    @DisplayName("Verifier should accept a message that contains more credentials as requested")
    @MandatoryTest
    void presentationResponse_tooManyCredentials() {

    }

    @DisplayName("Verifier should reject an ID token that does not contain an access token")
    @MandatoryTest
    void presentationResponse_idTokenNoTokenClaim() {

    }

    @DisplayName("Verifier should reject an empty Presentations array")
    @MandatoryTest
    void presentationResponse_emptyPresentations() {

    }

    @DisplayName("Verifier should accept a Presentation with no Credentials")
    @MandatoryTest
    void presentationResponse_emptyCredentials() {

    }

    @DisplayName("Verifier should reject Presentations where the holder does not match the credentialSubject.id")
    void presentationResponse_holderNotEqualSubjectId() {

    }

    @DisplayName("Verifier should reject Presentations where at least 1 credential is revoked/suspended")
    void presentationResponse_credentialRevoked() {

    }

    @DisplayName("Verifier should reject Presentations where at least 1 credential schema is violated")
    void presentationResponse_invalidCredentialSchema() {

    }
}


package org.eclipse.dataspacetck.dcp.verification.presentation.verifier;

import com.nimbusds.jwt.JWTClaimsSet;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.PresentationFlow;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Date;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.VERIFIER;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.TOKEN;

@PresentationFlow
@ExtendWith(SystemBootstrapExtension.class)
public class AbstractVerifierPresentationFlowTest {
    @Inject
    @Did(VERIFIER)
    protected String verifierDid;
    @Inject
    @Did(HOLDER)
    protected String holderDid;
    @Inject
    @Holder
    protected KeyService holderKeyService;

    @NotNull
    protected static String createTriggerMessage() {
        return """
                {
                    "@type":  "https://w3id.org/dspace/2024/1/CatalogRequestMessage",
                    "https://w3id.org/dspace/v0.8/filter": {}
                }
                """;
    }

    protected String createIdToken(String authToken) {

        var claimSet = new JWTClaimsSet.Builder()
                .issuer(holderDid)
                .subject(holderDid)
                .audience(verifierDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)));

        if (authToken != null) {
            claimSet.claim(TOKEN, authToken);
        }

        return holderKeyService.sign(emptyMap(), claimSet.build());
    }

    @NotNull
    protected Request createRequest(String triggerEndpoint, String authHeader, String triggerMessage) {
        return new Request.Builder()
                .url(triggerEndpoint)
                .header("Authorization", authHeader)
                .post(RequestBody.create(triggerMessage, MediaType.parse("application/json")))
                .build();
    }
}

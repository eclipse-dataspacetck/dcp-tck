/*
 *  Copyright (c) 2025 Metaform Systems Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems Inc. - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.verification.issuance.cs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Credential;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.IssuanceFlow;
import org.eclipse.dataspacetck.dcp.system.annotation.Issuer;
import org.eclipse.dataspacetck.dcp.system.annotation.ThirdParty;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;
import org.eclipse.dataspacetck.dcp.verification.fixtures.TestFixtures;
import org.junit.jupiter.api.extension.ExtendWith;
import tools.jackson.databind.ObjectMapper;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JOSEObjectType.JWT;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.DAYS;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.ISSUER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.THIRD_PARTY;
import static org.eclipse.dataspacetck.dcp.system.model.vc.CredentialFormat.VC1_0_JWT;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_CREDENTIAL_TYPE;

@IssuanceFlow
@ExtendWith(SystemBootstrapExtension.class)
public class AbstractCredentialIssuanceTest {
    protected final ObjectMapper mapper = new ObjectMapper();

    @Inject
    @Did(ISSUER)
    protected String issuerDid;

    @Inject
    @Did(HOLDER)
    protected String holderDid;

    @Inject
    @Credential(MEMBERSHIP_CREDENTIAL_TYPE)
    protected VcContainer membershipCredential;

    @Inject
    @Credential(SENSITIVE_DATA_CREDENTIAL_TYPE)
    protected VcContainer sensitiveDataCredential;

    @Inject
    @Issuer
    protected KeyService issuerKeyService;

    @Inject
    @Did(THIRD_PARTY)
    protected String thirdPartyDid;

    @Inject
    @ThirdParty
    protected KeyService thirdPartyKeyService;

    protected JWTClaimsSet.Builder createClaims() {
        return new JWTClaimsSet.Builder()
                .audience(holderDid)
                .issuer(issuerDid)
                .subject(issuerDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)));
    }

    protected String createToken(JWTClaimsSet claims) {
        return issuerKeyService.sign(emptyMap(), claims);
    }

    /**
     * Signs a token with the issuer's key but under a key id that resolves to no verification method.
     */
    protected String createTokenWithUnknownKid(JWTClaimsSet claims) {
        return issuerKeyService.sign(Map.of("kid", issuerDid + "#unresolvable-" + randomUUID()), claims);
    }

    /**
     * Signs a token whose iss/sub is a DID that cannot be resolved, so the receiver cannot obtain a key at all.
     */
    protected String createTokenWithUnresolvableSubject(JWTClaimsSet.Builder claims) {
        var unresolvable = TestFixtures.unresolvableDid(issuerDid);
        var built = claims.issuer(unresolvable).subject(unresolvable).build();
        return issuerKeyService.sign(Map.of("kid", unresolvable + "#" + issuerKeyService.getPublicKey().getKeyID()), built);
    }

    /**
     * Signs a token with a freshly generated key that is not present in any DID document, while reusing the issuer's
     * key id so the receiver has to verify the signature rather than merely resolve the key.
     */
    protected String createTokenWithUnknownKey(JWTClaimsSet claims) throws JOSEException {
        var spoofedKey = new ECKeyGenerator(Curve.P_256)
                .keyID(issuerKeyService.getPublicKey().getKeyID())
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        var header = new JWSHeader.Builder(ES256).type(JWT)
                .keyID(claims.getClaim("iss") + "#" + spoofedKey.getKeyID())
                .build();

        var signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new ECDSASigner(spoofedKey.toECPrivateKey()));
        return signedJwt.serialize();
    }

    /**
     * Generates a credential of the given type, signed by the given key service and claiming {@code issuerDid} as its
     * issuer. Passing a key service other than the issuer's produces a credential whose proof cannot be verified
     * against the issuer's DID document.
     */
    protected VcContainer createCredential(String credentialType, String subjectId, KeyService signingKeyService) {
        var credential = VerifiableCredential.Builder.newInstance()
                .id("urn:uuid:" + randomUUID())
                .issuer(issuerDid)
                .issuanceDate(now().toString())
                .expirationDate(now().plus(1, DAYS).toString())
                .type(List.of("VerifiableCredential", credentialType))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .credentialSubject(Map.of("id", subjectId, "test", "test"))
                .build();

        var raw = new JwtCredentialGenerator(issuerDid, signingKeyService).generateCredential(credential);
        return new VcContainer(credentialType, raw.getContent(), credential, VC1_0_JWT);
    }

    /**
     * Builds the {@code credentials} entry of a {@code CredentialMessage} for the given containers.
     */
    protected List<Map<String, Object>> credentialContainers(VcContainer... containers) {
        return Arrays.stream(containers)
                .map(c -> Map.<String, Object>of(
                        "credentialType", c.credentialType(),
                        "format", c.format().profileString,
                        "payload", c.rawCredential()))
                .toList();
    }
}

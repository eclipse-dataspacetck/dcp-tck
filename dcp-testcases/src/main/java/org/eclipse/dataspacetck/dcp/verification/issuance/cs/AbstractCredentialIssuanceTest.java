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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Credential;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.IssuanceFlow;
import org.eclipse.dataspacetck.dcp.system.annotation.Issuer;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Date;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.ISSUER;
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

}

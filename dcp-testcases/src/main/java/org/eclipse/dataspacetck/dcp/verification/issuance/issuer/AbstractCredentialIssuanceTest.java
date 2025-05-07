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

package org.eclipse.dataspacetck.dcp.verification.issuance.issuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.core.api.system.Inject;
import org.eclipse.dataspacetck.core.system.SystemBootstrapExtension;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.IssuerService;
import org.eclipse.dataspacetck.dcp.system.annotation.RoleType;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.message.DcpMessageBuilder;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.time.Instant.now;
import static java.util.Collections.emptyMap;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.annotation.RoleType.HOLDER;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.CREDENTIAL_REQUEST_MESSAGE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.SENSITIVE_DATA_CREDENTIAL_TYPE;

@IssuerService
@ExtendWith(SystemBootstrapExtension.class)
public abstract class AbstractCredentialIssuanceTest {

    protected final ObjectMapper mapper = new ObjectMapper();
    @Inject
    @Did(HOLDER)
    protected String holderDid;
    @Inject
    @Holder
    protected KeyService holderKeyService;
    @Inject
    @Did(RoleType.ISSUER)
    protected String issuerDid;

    protected DcpMessageBuilder createCredentialRequestMessage(String holderPid) {
        return DcpMessageBuilder.newInstance()
                .type(CREDENTIAL_REQUEST_MESSAGE_TYPE)
                .property("holderPid", holderPid)
                .property("credentials", List.of(
                        Map.of(
                                "credentialType", MEMBERSHIP_CREDENTIAL_TYPE,
                                "format", "VC1_0_JWT"
                        ),
                        Map.of(
                                "credentialType", SENSITIVE_DATA_CREDENTIAL_TYPE,
                                "format", "VC1_0_JWT"
                        )
                ));
    }

    protected JWTClaimsSet.Builder createClaims() {
        return new JWTClaimsSet.Builder()
                .audience(issuerDid)
                .issuer(holderDid)
                .subject(holderDid)
                .jwtID(randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(now().plusSeconds(600)));
    }

    protected String createToken(JWTClaimsSet claims) {
        return holderKeyService.sign(emptyMap(), claims);
    }

}

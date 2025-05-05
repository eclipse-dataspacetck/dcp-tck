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

package org.eclipse.dataspacetck.dcp.system.generation;

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VP;

/**
 * Generates JWT-based VPs.
 */
public class JwtPresentationGenerator implements PresentationGenerator {
    private final String issuerDid;
    private final KeyService keyService;

    public JwtPresentationGenerator(String issuerDid, KeyService keyService) {
        this.keyService = keyService;
        this.issuerDid = issuerDid;
    }

    @Override
    public PresentationFormat getFormat() {
        return PresentationFormat.JWT;
    }

    @Override
    public Result<String> generatePresentation(
            String audience,
            String holderDid,
            List<VcContainer> credentials) {

        // VP token: contains the actual VP as "vp" claim

        var now = new Date();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .audience(audience)
                .subject(holderDid)
                .jwtID(randomUUID().toString())
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(Date.from(now.toInstant().plusSeconds(300)))
                .claim(VP, createVpToken(credentials))
                .build();

        var keyId = issuerDid + "#" + keyService.getPublicKey().getKeyID();
        return Result.success(keyService.sign(Map.of("kid", keyId), claims));
    }

    private Map<String, Object> createVpToken(List<VcContainer> credentials) {
        return Map.of(
                "context", List.of("https://www.w3.org/2018/credentials/v1", "https://identity.foundation/presentation-exchange/submission/v1"),
                "type", "VerifiablePresentation",
                "verifiableCredential", credentials.stream().map(VcContainer::rawCredential).toList()
        );
    }

}

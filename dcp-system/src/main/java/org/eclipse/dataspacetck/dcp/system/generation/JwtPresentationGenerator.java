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

import static java.time.Instant.now;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.VC;

/**
 * Generates JWT-based VPs.
 */
public class JwtPresentationGenerator implements PresentationGenerator {
    private KeyService keyService;
    private final String issuerDid;

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

        var now = new Date();
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuerDid)
                .audience(audience)
                .subject(holderDid)
                .claim("jti", randomUUID())
                .notBeforeTime(now)
                .issueTime(now)
                .expirationTime(Date.from(now().plusSeconds(300)))
                .claim(VC, credentials.stream().map(VcContainer::rawCredential).toList())
                .build();

        var keyId = issuerDid + "#" + keyService.getPublicKey().getKeyID();
        return Result.success(keyService.sign(Map.of("kid", keyId), claims));
    }


}

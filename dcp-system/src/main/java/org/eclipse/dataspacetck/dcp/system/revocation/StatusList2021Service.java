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

package org.eclipse.dataspacetck.dcp.system.revocation;

import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class StatusList2021Service implements CredentialRevocationService {
    public static final String REVOCATION = "revocation";
    private static final int LENGTH = 16 * 1024; // 16k bits
    private final BitString bitstring = BitString.Builder.newInstance().size(LENGTH).build();
    private final String credentialId = UUID.randomUUID().toString();
    private final String issuerDid;
    private final String address;

    public StatusList2021Service(String issuerDid, String address) {
        this.issuerDid = issuerDid;
        this.address = address;
    }

    @Override
    public void setRevoked(int statusListIndex) {
        if (statusListIndex >= LENGTH || statusListIndex < 0) {
            throw new IndexOutOfBoundsException("Index out of range: " + statusListIndex);
        }
        bitstring.set(statusListIndex, true);
    }

    @Override
    public VerifiableCredential createStatusListCredential() {
        var credential = VerifiableCredential.Builder.newInstance()
                .id(credentialId)
                .type(List.of("VerifiableCredential", "StatusList2021Credential"))
                .issuer(issuerDid)
                .issuanceDate(Instant.now().toString())
                .context(List.of("https://www.w3.org/2018/credentials/v1", "https://w3id.org/vc/status-list/2021/v1"))
                .credentialSubject(Map.of(
                        "id", credentialId,
                        "type", "StatusList2021",
                        "statusPurpose", REVOCATION,
                        "encodedList", generateEncodedStatusList()
                ));

        return credential.build();
    }

    @Override
    public String getCredentialId() {
        return credentialId;
    }

    @Override
    public boolean isRevoked(int statusListIndex) {
        return bitstring.get(statusListIndex);
    }


    /**
     * Generates the Base64-encoded, GZIP-compressed bitstring
     */
    public String generateEncodedStatusList() {
        return "u" + BitString.Writer.newInstance().encoder(Base64.getUrlEncoder().withoutPadding()).write(bitstring).getContent();
    }

    @Override
    public String getAddress() {
        return address;
    }

    @Override
    public String getStatusEntryType() {
        return "StatusList2021Entry";
    }

}

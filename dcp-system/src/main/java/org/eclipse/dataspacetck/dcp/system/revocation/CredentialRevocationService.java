package org.eclipse.dataspacetck.dcp.system.revocation;

import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;

public interface CredentialRevocationService {

    void setRevoked(int statusListIndex);

    VerifiableCredential createStatusListCredential();

    boolean isRevoked(int statusListIndex);

    String getCredentialId();
}

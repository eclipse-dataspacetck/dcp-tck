package org.eclipse.dataspacetck.dcp.system.cs;

import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public  class CredentialServiceAdapter implements CredentialService {
    @Override
    public Result<Map<String, Object>> presentationQueryMessage(String bearerDid, String accessToken, Map<String, Object> message) {
        return null;
    }

    @Override
    public Result<Void> writeCredentials(String idTokenJwt, Map<String, Object> credentialMessage) {
        return null;
    }

    @Override
    public Result<Void> offerCredentials(String idTokenJwt, InputStream body) {
        return null;
    }

    @Override
    public Collection<VcContainer> getCredentials() {
        return List.of();
    }

    @Override
    public void withDelegate(CredentialService delegate) {
        throw new UnsupportedOperationException();
    }
}

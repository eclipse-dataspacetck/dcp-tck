package org.eclipse.dataspacetck.dcp.system.revocation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.function.Function;

public record CredentialRevocationHandler(CredentialRevocationService revocationService,
                                          ObjectMapper mapper) implements Function<InputStream, String> {

    @Override
    public String apply(InputStream inputStream) {
        var cred = revocationService.createStatusListCredential();
        try {
            return mapper.writeValueAsString(cred);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

package org.eclipse.dataspacetck.dcp.system.sts;

import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.util.List;

/**
 * A local test STS.
 */
public interface SecureTokenServer extends StsClient {

    /**
     * Validates an issued read token for the given bearer. The token will be expired if valid.
     */
    Result<List<String>> validateReadToken(String bearerDid, String token);

    /**
     * Authorize a write operation with scopes for the given bearer and correlation id.
     */
    void authorizeWrite(String bearerDid, String correlationId, List<String> scopes);

    /**
     * Validates a write operation.
     */
    Result<List<String>> validateWrite(String bearerDid, String correlationId);

}

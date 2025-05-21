package org.eclipse.dataspacetck.dcp.system.revocation;

import org.eclipse.dataspacetck.dcp.system.model.vc.VerifiableCredential;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;

public class BitstringStatusListService implements CredentialRevocationService {
    public static final String REVOCATION = "revocation";
    private final BitSet statusBits = new BitSet();
    private static final int LENGTH = 16 * 1024;
    private final String credentialId = UUID.randomUUID().toString();
    private final String issuerDid;

    public BitstringStatusListService(String issuerDid) {
        this.issuerDid = issuerDid;
    }

    @Override
    public void setRevoked(int statusListIndex) {
        if (statusListIndex >= LENGTH || statusListIndex < 0) {
            throw new IndexOutOfBoundsException("Index out of range: " + statusListIndex);
        }
        statusBits.set(statusListIndex, true);
    }

    @Override
    public VerifiableCredential createStatusListCredential() {
        var credential = VerifiableCredential.Builder.newInstance()
                .id(credentialId)
                .type(List.of("VerifiableCredential", "BitstringStatusListCredential"))
                .issuer(issuerDid)
                .issuanceDate(Instant.now().toString())
                .context(List.of("https://www.w3.org/ns/credentials/v2"))
                .credentialSubject(Map.of(
                        "id", credentialId,
                        "type", "BitstringStatusList",
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
        return statusBits.get(statusListIndex);
    }


    /**
     * Generates the Base64-encoded, GZIP-compressed bitstring
     */
    public String generateEncodedStatusList()  {
        byte[] rawBytes = statusBits.toByteArray();
        byte[] compressed = gzipCompress(rawBytes);
        return Base64.getEncoder().encodeToString(compressed);
    }

    private byte[] gzipCompress(byte[] data)  {
        try (
                var byteStream = new ByteArrayOutputStream();
                var gzipStream = new GZIPOutputStream(byteStream)
        ) {
            gzipStream.write(data);
            gzipStream.finish();
            return byteStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

package org.eclipse.dataspacetck.dcp.system.handler;

import org.eclipse.dataspacetck.core.api.system.HandlerResponse;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

public class SchemaProvider extends AbstractProtocolHandler {

    public SchemaProvider() {
        super("/credential-schemas/membership-credential-schema.json");
    }

    @Override
    public HandlerResponse apply(Map<String, List<String>> headers, InputStream body) {
        var schemaJson = schema.getSchemaNode().toString();
        return new HandlerResponse(200, schemaJson, Map.of(
                "Content-Type", "application/schema+json"
        ));
    }

}

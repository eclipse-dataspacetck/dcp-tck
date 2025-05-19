package org.eclipse.dataspacetck.dcp.system.verifier;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record PresentationResponseMessage(@JsonProperty("presentation") List<String> presentations,
                                          @JsonProperty("type") String type) {
}

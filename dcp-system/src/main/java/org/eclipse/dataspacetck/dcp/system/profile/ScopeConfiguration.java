/*
 *  Copyright (c) 2025 TNO
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       TNO - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.system.profile;

import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;

import java.util.Locale;
import java.util.regex.Pattern;

import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_PREFIX;
import static org.eclipse.dataspacetck.dcp.system.cs.CredentialServiceImpl.DEFAULT_SCOPE_PATTERN;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE;

/**
 * Defines how credential types are mapped to scopes and extracted from scopes.
 */
public class ScopeConfiguration {
    private static final String SCOPE_PATTERN_PROPERTY = TCK_PREFIX + ".vc.scope.pattern";
    private static final Pattern CANONICAL_SCOPE_PATTERN = DEFAULT_SCOPE_PATTERN;

    private final ServiceConfiguration configuration;
    private final Pattern configuredScopePattern;

    public ScopeConfiguration(ServiceConfiguration configuration, Pattern configuredScopePattern) {
        this.configuration = configuration;
        this.configuredScopePattern = configuredScopePattern;
    }

    public static ScopeConfiguration from(ServiceConfiguration configuration) {
        var pattern = Pattern.compile(configuration.getPropertyAsString(
                SCOPE_PATTERN_PROPERTY, DEFAULT_SCOPE_PATTERN.pattern()));
        return new ScopeConfiguration(configuration, pattern);
    }

    public Pattern getPattern() {
        return configuredScopePattern;
    }

    public String getScope(String credentialType) {
        var property = TCK_PREFIX + ".vc.scope." + credentialType.toLowerCase(Locale.ROOT);
        var scope = configuration.getPropertyAsString(property, SCOPE_TYPE + credentialType);
        var matcher = configuredScopePattern.matcher(scope);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                    "Configured scope pattern does not match scope from '" + property + "': " + scope);
        }
        if (!credentialType.equals(matcher.group("type"))) {
            throw new IllegalArgumentException(
                    "Configured scope pattern extracts an unexpected credential type from '" + property + "': " + scope);
        }
        return scope;
    }

    /**
     * Replaces a DCP credential type scope with its configured value. Other literal scopes are preserved.
     */
    public String mapToConfiguredScope(String scope) {
        var matcher = CANONICAL_SCOPE_PATTERN.matcher(scope);
        return matcher.matches() ? getScope(matcher.group("type")) : scope;
    }
}

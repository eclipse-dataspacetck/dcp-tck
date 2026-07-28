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

package org.eclipse.dataspacetck.dcp.system.profile;

import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.eclipse.dataspacetck.dcp.system.cs.CredentialServiceImpl.DEFAULT_SCOPE_PATTERN;
import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE;
import static org.eclipse.dataspacetck.dcp.system.profile.TestProfile.MEMBERSHIP_CREDENTIAL_TYPE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScopeConfigurationTest {
    private static final String PATTERN_PROPERTY = "dataspacetck.vc.scope.pattern";
    private static final String MEMBERSHIP_SCOPE_PROPERTY = "dataspacetck.vc.scope.membershipcredential";

    private final ServiceConfiguration configuration = mock();

    @Test
    void createsDefaultScope() {
        var defaultScope = SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE;
        when(configuration.getPropertyAsString(PATTERN_PROPERTY, DEFAULT_SCOPE_PATTERN.pattern()))
                .thenReturn(DEFAULT_SCOPE_PATTERN.pattern());
        when(configuration.getPropertyAsString(MEMBERSHIP_SCOPE_PROPERTY, defaultScope)).thenReturn(defaultScope);

        var scopeConfiguration = ScopeConfiguration.from(configuration);

        assertThat(scopeConfiguration.getScope(MEMBERSHIP_CREDENTIAL_TYPE)).isEqualTo(defaultScope);
    }

    @Test
    void createsConfiguredScopeWithSuffix() {
        var scope = SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE + ":read";
        when(configuration.getPropertyAsString(PATTERN_PROPERTY, DEFAULT_SCOPE_PATTERN.pattern()))
                .thenReturn(DEFAULT_SCOPE_PATTERN.pattern());
        when(configuration.getPropertyAsString(MEMBERSHIP_SCOPE_PROPERTY, SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE))
                .thenReturn(scope);

        var scopeConfiguration = ScopeConfiguration.from(configuration);

        assertThat(scopeConfiguration.getScope(MEMBERSHIP_CREDENTIAL_TYPE)).isEqualTo(scope);
    }

    @Test
    void resolvesDefaultScopeToConfiguredScope() {
        var pattern = Pattern.compile("custom:(?<type>[^:]+):read");
        var scope = "custom:" + MEMBERSHIP_CREDENTIAL_TYPE + ":read";
        when(configuration.getPropertyAsString(MEMBERSHIP_SCOPE_PROPERTY, SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE))
                .thenReturn(scope);
        var scopeConfiguration = new ScopeConfiguration(configuration, pattern);

        assertThat(scopeConfiguration.resolveScope(SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE)).isEqualTo(scope);
    }

    @Test
    void preservesLiteralScope() {
        var scopeConfiguration = new ScopeConfiguration(configuration, DEFAULT_SCOPE_PATTERN);

        assertThat(scopeConfiguration.resolveScope("custom:literal:scope")).isEqualTo("custom:literal:scope");
    }

    @Test
    void rejectsScopeThatDoesNotMatchPattern() {
        var scope = "invalid-scope";
        when(configuration.getPropertyAsString(MEMBERSHIP_SCOPE_PROPERTY, SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE))
                .thenReturn(scope);

        var scopeConfiguration = new ScopeConfiguration(configuration, DEFAULT_SCOPE_PATTERN);

        assertThatThrownBy(() -> scopeConfiguration.getScope(MEMBERSHIP_CREDENTIAL_TYPE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(MEMBERSHIP_SCOPE_PROPERTY);
    }

    @Test
    void rejectsScopeForDifferentCredentialType() {
        var scope = SCOPE_TYPE + "OtherCredential";
        when(configuration.getPropertyAsString(MEMBERSHIP_SCOPE_PROPERTY, SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE))
                .thenReturn(scope);

        var scopeConfiguration = new ScopeConfiguration(configuration, DEFAULT_SCOPE_PATTERN);

        assertThatThrownBy(() -> scopeConfiguration.getScope(MEMBERSHIP_CREDENTIAL_TYPE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unexpected credential type");
    }
}

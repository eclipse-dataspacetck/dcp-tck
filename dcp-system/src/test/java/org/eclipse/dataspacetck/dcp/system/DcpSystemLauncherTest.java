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

package org.eclipse.dataspacetck.dcp.system;

import org.eclipse.dataspacetck.core.spi.system.ServiceConfiguration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher.resolveHolderPid;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DcpSystemLauncherTest {
    private static final String GLOBAL_PID = "global-correlation-id";
    private static final String TEST_METHOD = "cs_06_05_01_credentialMessage_rejectedStatus";
    private static final String CLASS_SCOPE =
            "[engine:junit-jupiter]/[class:org.eclipse.dataspacetck.dcp.verification.issuance.cs.CredentialIssuanceTest]";
    private static final String METHOD_SCOPE = CLASS_SCOPE + "/[method:" + TEST_METHOD + "(java.lang.String)]";
    private static final String OVERRIDE_PROPERTY = "dataspacetck.credentials.correlation.id." + TEST_METHOD;

    private final ServiceConfiguration configuration = mock();

    @Test
    void resolveHolderPid_whenTestDeclaresOverride() {
        when(configuration.getScopeId()).thenReturn(METHOD_SCOPE);
        when(configuration.getPropertyAsString(eq(OVERRIDE_PROPERTY), any())).thenReturn("per-test-id");

        assertThat(resolveHolderPid(configuration, GLOBAL_PID)).isEqualTo("per-test-id");
    }

    @Test
    void resolveHolderPid_whenNoOverrideConfigured() {
        when(configuration.getScopeId()).thenReturn(METHOD_SCOPE);
        when(configuration.getPropertyAsString(any(), any())).thenReturn(null);

        assertThat(resolveHolderPid(configuration, GLOBAL_PID)).isEqualTo(GLOBAL_PID);
    }

    /**
     * An override is keyed on the test method, so a class-level scope has nothing to key on.
     */
    @Test
    void resolveHolderPid_whenClassLevelScope() {
        when(configuration.getScopeId()).thenReturn(CLASS_SCOPE);

        assertThat(resolveHolderPid(configuration, GLOBAL_PID)).isEqualTo(GLOBAL_PID);
    }

    @Test
    void resolveHolderPid_whenScopeIdMissing() {
        when(configuration.getScopeId()).thenReturn(null);

        assertThat(resolveHolderPid(configuration, GLOBAL_PID)).isEqualTo(GLOBAL_PID);
    }
}

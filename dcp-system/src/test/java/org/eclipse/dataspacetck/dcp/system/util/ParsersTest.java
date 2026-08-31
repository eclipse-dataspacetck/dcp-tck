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

package org.eclipse.dataspacetck.dcp.system.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ParsersTest {

    private static final String CLASS_SEGMENT =
            "[engine:junit-jupiter]/[class:org.eclipse.dataspacetck.dcp.verification.issuance.cs.CredentialIssuanceTest]";

    @Test
    void parse_token() {
        assertThat(Parsers.parseBearerToken("Bearer token")).isEqualTo("token");
    }

    @Test
    void parseTestMethodName_whenMethodSegment() {
        assertThat(Parsers.parseTestMethodName(CLASS_SEGMENT + "/[method:cs_06_05_01_credentialMessage()]"))
                .contains("cs_06_05_01_credentialMessage");
    }

    @Test
    void parseTestMethodName_whenMethodHasParameters() {
        assertThat(Parsers.parseTestMethodName(
                CLASS_SEGMENT + "/[method:cs_06_05_01_credentialMessage_rejectedStatus(java.lang.String)]"))
                .contains("cs_06_05_01_credentialMessage_rejectedStatus");
    }

    @Test
    void parseTestMethodName_whenTestTemplateInvocation() {
        assertThat(Parsers.parseTestMethodName(
                CLASS_SEGMENT + "/[test-template:someTest(java.lang.String)]/[test-template-invocation:#1]"))
                .contains("someTest");
    }

    @Test
    void parseTestMethodName_whenClassLevelScope() {
        // constructor injection resolves against a class-level context, so there is no test to key an override on
        assertThat(Parsers.parseTestMethodName(CLASS_SEGMENT)).isEmpty();
    }

    @Test
    void parseTestMethodName_whenNullOrUnrecognized() {
        assertThat(Parsers.parseTestMethodName(null)).isEmpty();
        assertThat(Parsers.parseTestMethodName("")).isEmpty();
        assertThat(Parsers.parseTestMethodName("not-a-unique-id")).isEmpty();
    }
}
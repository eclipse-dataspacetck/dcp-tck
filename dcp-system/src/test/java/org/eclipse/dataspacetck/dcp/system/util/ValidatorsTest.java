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

class ValidatorsTest {

    @Test
    void verify_validate() {
        assertThat(Validators.validateBearerTokenHeader("Bearer token")).isTrue();
    }

    @Test
    void verify_invalidToken() {
        assertThat(Validators.validateBearerTokenHeader("token")).isFalse();
        assertThat(Validators.validateBearerTokenHeader("Bearer ")).isFalse();
    }
}
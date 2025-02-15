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

import static org.eclipse.dataspacetck.dcp.system.message.DcpConstants.SCOPE_TYPE;

/**
 * Defines the profile used for testing, including scopes and credential types.
 */
public interface TestProfile {

    String MEMBERSHIP_CREDENTIAL_TYPE = "MembershipCredential";

    String MEMBERSHIP_SCOPE = SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE;

    String SENSITIVE_DATE_CREDENTIAL_TYPE = "SensitiveDateCredential";

    String SENSITIVE_DATE_SCOPE = SCOPE_TYPE + SENSITIVE_DATE_CREDENTIAL_TYPE;
}

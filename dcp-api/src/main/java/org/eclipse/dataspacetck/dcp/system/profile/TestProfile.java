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

/**
 * Defines the profile used for testing, including scopes and credential types.
 */
public interface TestProfile {

    String MEMBERSHIP_CREDENTIAL_TYPE = "MembershipCredential";

    String SCOPE_TYPE = "org.eclipse.dspace.dcp.vc.type:";

    String MEMBERSHIP_SCOPE = SCOPE_TYPE + MEMBERSHIP_CREDENTIAL_TYPE;

}

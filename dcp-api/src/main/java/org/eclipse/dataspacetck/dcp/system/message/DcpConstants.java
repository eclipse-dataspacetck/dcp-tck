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

package org.eclipse.dataspacetck.dcp.system.message;

/**
 * DCP message constants.
 */
public interface DcpConstants {

    String DCP_NAMESPACE = "https://w3id.org/dspace-dcp/v1.0/";

    String CONTEXT = "@context";

    String TYPE = "type";

    String PRESENTATION = "presentation";

    String SCOPE = "scope";

    String AUTHORIZATION = "Authorization";

    String PRESENTATION_QUERY_MESSAGE = "PresentationQueryMessage";

    String PRESENTATION_RESPONSE_MESSAGE = "PresentationResponseMessage";

    String CREDENTIAL_SERVICE_TYPE = "CredentialService";

}

/*
 *  Copyright (c) 2025 Metaform Systems Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems Inc. - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.system.cs;

import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.service.Result;

import java.io.InputStream;
import java.util.Collection;
import java.util.Map;

/**
 * Specialized delegates for the {@link CredentialService} interface. Each delegate is a functional interface that exposes one
 * particular method and contains default implementations for all the others. This allows for easier and fluent use of the delegate.
 */
public class Delegates {
    @FunctionalInterface
    public interface PresentationQuery extends CredentialService {
        @Override
        default void withDelegate(CredentialService delegate) {
            throw new UnsupportedOperationException();
        }

        @Override
        default Collection<VcContainer> getCredentials() {
            throw new UnsupportedOperationException();
        }

        @Override
        default Result<Void> offerCredentials(String idTokenJwt, InputStream body) {
            throw new UnsupportedOperationException();
        }

        @Override
        default Result<Void> writeCredentials(String idTokenJwt, Map<String, Object> credentialMessage) {
            throw new UnsupportedOperationException();
        }
    }

    //todo: add other delegates as needed
}

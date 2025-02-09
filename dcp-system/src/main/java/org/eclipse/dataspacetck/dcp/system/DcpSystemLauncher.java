/*
 *  Copyright (c) 2024 Metaform Systems, Inc.
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
import org.eclipse.dataspacetck.core.spi.system.ServiceResolver;
import org.eclipse.dataspacetck.core.spi.system.SystemConfiguration;
import org.eclipse.dataspacetck.core.spi.system.SystemLauncher;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderDid;
import org.eclipse.dataspacetck.dcp.system.annotation.Verifier;
import org.eclipse.dataspacetck.dcp.system.annotation.VerifierDid;
import org.eclipse.dataspacetck.dcp.system.assembly.BaseAssembly;
import org.eclipse.dataspacetck.dcp.system.assembly.ServiceAssembly;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.did.DidService;
import org.jetbrains.annotations.Nullable;

import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Instantiates and bootstraps a DCP test fixture. The test fixture consists of immutable base services and services which
 * are instantiated per test.
 */
public class DcpSystemLauncher implements SystemLauncher {
    private BaseAssembly baseAssembly;
    private Map<String, ServiceAssembly> serviceAssemblies = new ConcurrentHashMap<>();

    @Override
    public void start(SystemConfiguration configuration) {
        baseAssembly = new BaseAssembly(configuration);
    }

    @Override
    public <T> boolean providesService(Class<T> type) {
        return type.isAssignableFrom(CredentialService.class) ||
               type.isAssignableFrom(DidService.class) ||
               type.isAssignableFrom(KeyService.class);
    }

    @Nullable
    @Override
    public <T> T getService(Class<T> type, ServiceConfiguration configuration, ServiceResolver resolver) {
        var scopeId = configuration.getScopeId();
        var assembly = serviceAssemblies.computeIfAbsent(scopeId, id -> new ServiceAssembly(baseAssembly, resolver, configuration));
        if (type.isAssignableFrom(CredentialService.class)) {
            return type.cast(assembly.getCredentialService());
        } else if (type.isAssignableFrom(KeyService.class)) {
            return hasAnnotation(Verifier.class, configuration) ? type.cast(baseAssembly.getVerifierKeyService())
                    : type.cast(baseAssembly.getHolderKeyService());
        } else if (type.isAssignableFrom(DidService.class)) {
            return hasAnnotation(Verifier.class, configuration) ? type.cast(baseAssembly.getVerifierDidService())
                    : type.cast(baseAssembly.getHolderDidService());
        } else if (type.isAssignableFrom(String.class)) {
            if (hasAnnotation(VerifierDid.class, configuration)) {
                return type.cast(baseAssembly.getVerifierDid());
            } else if (hasAnnotation(HolderDid.class, configuration)) {
                return type.cast(baseAssembly.getHolderDid());
            }
        }
        return SystemLauncher.super.getService(type, configuration, resolver);
    }

    private boolean hasAnnotation(Class<? extends Annotation> annotation, ServiceConfiguration configuration) {
        return configuration.getAnnotations().stream().anyMatch(a -> a.annotationType().equals(annotation));
    }
}

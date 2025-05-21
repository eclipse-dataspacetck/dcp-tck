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
import org.eclipse.dataspacetck.dcp.system.annotation.AuthToken;
import org.eclipse.dataspacetck.dcp.system.annotation.Credential;
import org.eclipse.dataspacetck.dcp.system.annotation.Did;
import org.eclipse.dataspacetck.dcp.system.annotation.Holder;
import org.eclipse.dataspacetck.dcp.system.annotation.HolderPid;
import org.eclipse.dataspacetck.dcp.system.annotation.IssueCredentials;
import org.eclipse.dataspacetck.dcp.system.annotation.Issuer;
import org.eclipse.dataspacetck.dcp.system.annotation.ThirdParty;
import org.eclipse.dataspacetck.dcp.system.annotation.TriggerEndpoint;
import org.eclipse.dataspacetck.dcp.system.annotation.Verifier;
import org.eclipse.dataspacetck.dcp.system.assembly.BaseAssembly;
import org.eclipse.dataspacetck.dcp.system.assembly.ServiceAssembly;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.cs.CredentialService;
import org.eclipse.dataspacetck.dcp.system.did.DidService;
import org.eclipse.dataspacetck.dcp.system.generation.JwtCredentialGenerator;
import org.eclipse.dataspacetck.dcp.system.model.vc.VcContainer;
import org.eclipse.dataspacetck.dcp.system.revocation.CredentialRevocationService;
import org.jetbrains.annotations.Nullable;

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Instantiates and bootstraps a DCP test fixture. The test fixture consists of immutable base services and services which
 * are instantiated per test.
 */
public class DcpSystemLauncher implements SystemLauncher {
    private final Map<String, ServiceAssembly> serviceAssemblies = new ConcurrentHashMap<>();
    private BaseAssembly baseAssembly;

    @Override
    public void start(SystemConfiguration configuration) {
        baseAssembly = new BaseAssembly(configuration);
    }

    @Override
    public <T> boolean providesService(Class<T> type) {
        return type.isAssignableFrom(CredentialService.class) ||
                type.isAssignableFrom(CredentialRevocationService.class) ||
                type.isAssignableFrom(DidService.class) ||
                type.isAssignableFrom(String.class) ||
                type.isAssignableFrom(KeyService.class) ||
                type.isAssignableFrom(VcContainer.class);
    }

    @Nullable
    @Override
    public <T> T getService(Class<T> type, ServiceConfiguration configuration, ServiceResolver resolver) {
        var scopeId = configuration.getScopeId();
        var assembly = serviceAssemblies.computeIfAbsent(scopeId, id -> new ServiceAssembly(baseAssembly, resolver, configuration));
        if (type.isAssignableFrom(CredentialService.class)) {
            return type.cast(assembly.getCredentialService());
        } else if (type.isAssignableFrom(CredentialRevocationService.class)) {
            return type.cast(assembly.getRevocationService());
        } else if (type.isAssignableFrom(VcContainer.class)) {
            if (hasAnnotation(Credential.class, configuration)) {
                var gen = new JwtCredentialGenerator(baseAssembly.getIssuerDid(), baseAssembly.getIssuerKeyService());
                var credentialType = getAnnotation(Credential.class, configuration);
                if (credentialType.isPresent()) {
                    return type.cast(assembly.createVcContainer(baseAssembly.getIssuerDid(), baseAssembly.getHolderDid(), gen, credentialType.get().value()));
                }
            }
        } else if (type.isAssignableFrom(KeyService.class)) {
            if (hasAnnotation(Verifier.class, configuration)) {
                return type.cast(baseAssembly.getVerifierKeyService());
            } else if (hasAnnotation(Holder.class, configuration)) {
                return type.cast(baseAssembly.getHolderKeyService());
            } else if (hasAnnotation(ThirdParty.class, configuration)) {
                return type.cast(baseAssembly.getThirdPartyKeyService());
            } else if (hasAnnotation(Issuer.class, configuration)) {
                return type.cast(baseAssembly.getIssuerKeyService());
            }
        } else if (type.isAssignableFrom(DidService.class)) {
            if (hasAnnotation(Verifier.class, configuration)) {
                return type.cast(baseAssembly.getVerifierDidService());
            } else if (hasAnnotation(Holder.class, configuration)) {
                return type.cast(baseAssembly.getHolderDidService());
            } else if (hasAnnotation(ThirdParty.class, configuration)) {
                return type.cast(baseAssembly.getThirdPartyDidService());
            } else if (hasAnnotation(Issuer.class, configuration)) {
                return type.cast(baseAssembly.getIssuerDidService());
            }
        } else if (type.isAssignableFrom(String.class)) {
            if (hasAnnotation(AuthToken.class, configuration)) {
                return createAuthToken(type, configuration, assembly);
            }
            if (hasAnnotation(HolderPid.class, configuration)) {
                return type.cast(baseAssembly.getHolderPid());
            }
            if (hasAnnotation(TriggerEndpoint.class, configuration)) {
                return type.cast(baseAssembly.getVerifierTriggerEndpoint());
            }

            var did = getAnnotation(Did.class, configuration);
            if (did.isPresent()) {
                switch (did.get().value()) {
                    case HOLDER -> {
                        return type.cast(baseAssembly.getHolderDid());
                    }
                    case VERIFIER -> {
                        return type.cast(baseAssembly.getVerifierDid());
                    }
                    case THIRD_PARTY -> {
                        return type.cast(baseAssembly.getThirdPartyDid());
                    }
                    case ISSUER -> {
                        return type.cast(baseAssembly.getIssuerDid());
                    }
                    default -> throw new UnsupportedOperationException("Unsupported DID role: " + did.get().value());
                }
            }
        }
        return SystemLauncher.super.getService(type, configuration, resolver);
    }

    @Override
    public void beforeExecution(ServiceConfiguration configuration, ServiceResolver resolver) {
        if (hasAnnotation(IssueCredentials.class, configuration)) {
            serviceAssemblies.get(configuration.getScopeId()).issueCredentials(baseAssembly);
        }
    }

    private <T> T createAuthToken(Class<T> type, ServiceConfiguration configuration, ServiceAssembly assembly) {
        var scopes = Arrays.asList(getAnnotation(AuthToken.class, configuration).orElseThrow().value());
        var tokenResult = assembly.getStsClient().obtainReadToken(baseAssembly.getVerifierDid(), scopes);
        if (tokenResult.failed()) {
            throw new AssertionError(tokenResult.getFailure());
        }
        return type.cast(tokenResult.getContent());
    }

    private boolean hasAnnotation(Class<? extends Annotation> annotation, ServiceConfiguration configuration) {
        return configuration.getAnnotations().stream().anyMatch(a -> a.annotationType().equals(annotation));
    }

    @SuppressWarnings({"unchecked", "SameParameterValue"})
    private <A extends Annotation> Optional<A> getAnnotation(Class<A> annotation, ServiceConfiguration configuration) {
        return (Optional<A>) configuration.getAnnotations().stream()
                .filter(a -> a.annotationType().equals(annotation))
                .findFirst();
    }
}

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

package org.eclipse.dataspacetck.dcp.system.assembly;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.dataspacetck.core.spi.system.SystemConfiguration;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyService;
import org.eclipse.dataspacetck.dcp.system.crypto.KeyServiceImpl;
import org.eclipse.dataspacetck.dcp.system.crypto.Keys;
import org.eclipse.dataspacetck.dcp.system.cs.TokenValidationService;
import org.eclipse.dataspacetck.dcp.system.cs.TokenValidationServiceImpl;
import org.eclipse.dataspacetck.dcp.system.did.DidService;
import org.eclipse.dataspacetck.dcp.system.did.DidServiceImpl;

import java.net.URI;

import static java.lang.String.format;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_CALLBACK_ADDRESS;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_DEFAULT_CALLBACK_ADDRESS;

/**
 * Assembles immutable services that are used across test invocations.
 */
public class BaseAssembly {
    private String address;
    private String issuerDid;
    private KeyService issuerKeyService;
    private DidService issuerDidService;
    private String holderDid;
    private KeyService holderKeyService;
    private DidService holderDidService;
    private String verifierDid;
    private KeyService verifierKeyService;
    private DidService verifierDidService;
    private TokenValidationService verifierTokenService;
    private TokenValidationService holderTokenService;
    private ObjectMapper mapper;

    public ObjectMapper getMapper() {
        return mapper;
    }

    public String getAddress() {
        return address;
    }

    public String getVerifierDid() {
        return verifierDid;
    }

    public TokenValidationService getVerifierTokenService() {
        return verifierTokenService;
    }

    public KeyService getVerifierKeyService() {
        return verifierKeyService;
    }

    public DidService getVerifierDidService() {
        return verifierDidService;
    }

    public String getHolderDid() {
        return holderDid;
    }

    public KeyService getHolderKeyService() {
        return holderKeyService;
    }

    public DidService getHolderDidService() {
        return holderDidService;
    }

    public TokenValidationService getHolderTokenService() {
        return holderTokenService;
    }

    public String getIssuerDid() {
        return issuerDid;
    }

    public KeyService getIssuerKeyService() {
        return issuerKeyService;
    }

    public DidService getIssuerDidService() {
        return issuerDidService;
    }

    public BaseAssembly(SystemConfiguration configuration) {
        mapper = new ObjectMapper();
        address = configuration.getPropertyAsString(TCK_CALLBACK_ADDRESS, TCK_DEFAULT_CALLBACK_ADDRESS);
        verifierDid = parseDid("verifier");
        issuerDid = parseDid("issuer");
        issuerKeyService = new KeyServiceImpl(Keys.generateEcKey());
        issuerDidService = new DidServiceImpl(issuerDid, address, issuerKeyService);
        holderDid = parseDid("holder");
        holderKeyService = new KeyServiceImpl(Keys.generateEcKey());
        holderDidService = new DidServiceImpl(holderDid, address, holderKeyService);
        holderTokenService = new TokenValidationServiceImpl(holderDid);
        verifierTokenService = new TokenValidationServiceImpl(verifierDid);
        verifierKeyService = new KeyServiceImpl(Keys.generateEcKey());
        verifierDidService = new DidServiceImpl(verifierDid, address, verifierKeyService);
    }

    private String parseDid(String discriminator) {
        var uri = URI.create(address);
        return uri.getPort() != 443 ? format("did:web:%s%%3A%s:%s", uri.getHost(), uri.getPort(), discriminator)
                : format("did:web:%s:%s", uri.getHost(), discriminator);
    }
}

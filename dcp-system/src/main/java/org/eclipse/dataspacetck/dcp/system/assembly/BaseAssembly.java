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
import org.eclipse.dataspacetck.dcp.system.did.IssuerDidService;

import java.net.URI;
import java.util.Objects;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_CALLBACK_ADDRESS;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_DEFAULT_CALLBACK_ADDRESS;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_PREFIX;

/**
 * Assembles immutable services that are used across test invocations.
 */
public class BaseAssembly {
    private final String address;
    private final String issuerDid;
    private final KeyService issuerKeyService;
    private final DidService issuerDidService;
    private final String holderDid;
    private final KeyService holderKeyService;
    private final DidService holderDidService;
    private final String verifierDid;
    private final KeyService verifierKeyService;
    private final DidService verifierDidService;
    private final TokenValidationService verifierTokenService;
    private final TokenValidationService holderTokenService;
    private final TokenValidationService issuerTokenService;
    private final String thirdPartyDid;
    private final KeyServiceImpl thirdPartyKeyService;
    private final DidServiceImpl thirdPartyDidService;
    private final ObjectMapper mapper;
    private final String holderPid;

    public BaseAssembly(SystemConfiguration configuration) {
        mapper = new ObjectMapper();
        address = configuration.getPropertyAsString(TCK_CALLBACK_ADDRESS, TCK_DEFAULT_CALLBACK_ADDRESS);
        verifierDid = parseDid("verifier");
        issuerDid = parseDid("issuer");
        thirdPartyDid = parseDid("thirdparty");
        issuerKeyService = new KeyServiceImpl(Keys.generateEcKey());
        issuerDidService = new IssuerDidService(issuerDid, address, issuerKeyService);
        issuerTokenService = new TokenValidationServiceImpl(issuerDid);

        var hd = configuration.getPropertyAsString(TCK_PREFIX + ".did.holder", null);
        holderDid = Objects.requireNonNullElseGet(hd, () -> parseDid("holder"));
        holderKeyService = new KeyServiceImpl(Keys.generateEcKey());
        holderDidService = new DidServiceImpl(holderDid, address, holderKeyService);
        holderTokenService = new TokenValidationServiceImpl(holderDid);

        holderPid = ofNullable(configuration.getPropertyAsString(TCK_PREFIX + ".credentials.correlation.id", null)).orElseGet(() -> randomUUID().toString());

        verifierTokenService = new TokenValidationServiceImpl(verifierDid);
        verifierKeyService = new KeyServiceImpl(Keys.generateEcKey());
        verifierDidService = new DidServiceImpl(verifierDid, address, verifierKeyService);

        thirdPartyKeyService = new KeyServiceImpl(Keys.generateEcKey());
        thirdPartyDidService = new DidServiceImpl(thirdPartyDid, address, thirdPartyKeyService);
    }

    public TokenValidationService getIssuerTokenService() {
        return issuerTokenService;
    }

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

    public String getThirdPartyDid() {
        return thirdPartyDid;
    }

    public KeyServiceImpl getThirdPartyKeyService() {
        return thirdPartyKeyService;
    }

    public DidServiceImpl getThirdPartyDidService() {
        return thirdPartyDidService;
    }

    private String parseDid(String discriminator) {
        var uri = URI.create(address);
        return uri.getPort() != 443 ? format("did:web:%s%%3A%s:%s", uri.getHost(), uri.getPort(), discriminator)
                : format("did:web:%s:%s", uri.getHost(), discriminator);
    }

    public String getHolderPid() {
        return holderPid;
    }

}

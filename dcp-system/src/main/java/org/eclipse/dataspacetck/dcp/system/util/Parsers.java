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

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Message parsers
 */
public final class Parsers {

    /**
     * Matches the method segment of a JUnit Platform unique id, capturing the bare method name. Test templates are
     * matched as well so parameterized tests resolve to the same name as ordinary ones.
     */
    private static final Pattern TEST_METHOD_SEGMENT = Pattern.compile("\\[(?:method|test-template):([^(\\]]+)");

    public static String parseBearerToken(String token) {
        return token.substring("Bearer ".length());
    }

    /**
     * Extracts the test method name from a JUnit Platform unique id, which is the only carrier of test identity the
     * TCK framework exposes to a launcher (via {@code ServiceConfiguration.getScopeId()}).
     * <p>
     * For example {@code [engine:junit-jupiter]/[class:Foo]/[method:myTest(java.lang.String)]} yields {@code myTest}.
     *
     * @param scopeId the scope id, may be null.
     * @return the method name, or empty for a class-level scope id or an unrecognized format.
     */
    public static Optional<String> parseTestMethodName(String scopeId) {
        if (scopeId == null) {
            return Optional.empty();
        }
        var matcher = TEST_METHOD_SEGMENT.matcher(scopeId);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    private Parsers() {
    }
}

/*
 *  Copyright (c) 2026 Think-it GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Think-it GmbH - initial API and implementation
 *
 */

package org.eclipse.dataspacetck.dcp.system.annotation;

import org.eclipse.dataspacetck.core.api.system.Inject;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * For field injection, used in conjunction with {@link Inject} to specify a service whose DID document
 * has no capabilityInvocation relationship for its verification method.
 */
@Inherited
@Retention(RUNTIME)
@Target({FIELD, PARAMETER})
public @interface NoCapability {
}

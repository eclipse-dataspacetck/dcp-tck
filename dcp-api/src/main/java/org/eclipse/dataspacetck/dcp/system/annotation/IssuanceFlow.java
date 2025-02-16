package org.eclipse.dataspacetck.dcp.system.annotation;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Tests that verify the issuance flow for a Credential Service implementation.
 */
@Inherited
@Retention(RUNTIME)
@Target({ METHOD, TYPE })
@Test
@Tag("IssuanceFlow")
public @interface IssuanceFlow {
}

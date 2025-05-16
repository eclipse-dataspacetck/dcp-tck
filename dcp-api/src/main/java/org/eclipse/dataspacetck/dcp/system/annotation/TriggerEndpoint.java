package org.eclipse.dataspacetck.dcp.system.annotation;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Used to inject a configurable endpoint at which the Verifier-Under-Test expects the DCP Presentation Flow to be kicked off.
 */
@Inherited
@Retention(RUNTIME)
@Target({ FIELD, PARAMETER })
public @interface TriggerEndpoint {
}

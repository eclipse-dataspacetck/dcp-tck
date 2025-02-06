import org.eclipse.dataspacetck.gradle.plugins.tckgen.TckGeneratorExtension

/*
 *  Copyright (c) 2025 Metaform Systems, Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform systems, Inc. - initial API and implementation
 *
 *
 */

plugins {
    alias(libs.plugins.tck.generator)
}

dependencies {
    implementation(libs.tck.common.api)
    implementation(rootProject.libs.tck.dsp.core)
    implementation(project(":dcp-api"))
    testImplementation(project(":dcp-system"))
}

tasks.test {
    systemProperty("dataspacetck.launcher", "org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher")
}

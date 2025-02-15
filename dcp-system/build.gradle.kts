/*
 *  Copyright (c) 2023 Metaform Systems, Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems, Inc. - initial API and implementation
 *
 *
 */

dependencies {
    implementation(rootProject.libs.tck.dsp.core)
    implementation(rootProject.libs.nimbus.jwt)
    implementation(rootProject.libs.bouncyCastle.bcprovJdk18on)
    implementation(rootProject.libs.schema.validator) {
        exclude("com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml")
    }

    api(project(":dcp-api"))
}

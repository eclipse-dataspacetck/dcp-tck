/*
 *
 *   Copyright (c) 2025 Metaform Systems, Inc.
 *
 *   See the NOTICE file(s) distributed with this work for additional
 *   information regarding copyright ownership.
 *
 *   This program and the accompanying materials are made available under the
 *   terms of the Apache License, Version 2.0 which is available at
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 *
 */

import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.eclipse.dataspacetck.gradle.tckbuild.extensions.DockerExtension

plugins {
    `java-library`
    id("application")
    alias(libs.plugins.shadow)
}

dependencies {
    implementation(rootProject.libs.tck.dsp.core)
    implementation(rootProject.libs.tck.dsp.tck.runtime)
    implementation(libs.junit.platform.launcher)

    implementation(project(":dcp-api"))
    implementation(project(":dcp-system"))
    implementation(project(":dcp-testcases"))
}


configure<DockerExtension> {
    jarFilePath = "build/libs/${project.name}-runtime.jar"
}
tasks.withType<ShadowJar> {
    exclude("**/pom.properties", "**/pom.xml")
    mergeServiceFiles()
    archiveFileName.set("${project.name}-runtime.jar") // should be something other than "dsp-tck.jar", to avoid erroneous task dependencies

}

application {
    mainClass.set("org.eclipse.dataspacetck.dcp.suite.DcpTckSuite")
}
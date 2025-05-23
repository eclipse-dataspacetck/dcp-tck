import org.eclipse.dataspacetck.gradle.tckbuild.extensions.TckBuildExtension

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


plugins {
    `java-library`
    `maven-publish`
    signing
    checkstyle
    jacoco
    `jacoco-report-aggregation`
    alias(libs.plugins.docker)
    alias(libs.plugins.nexuspublishing)
    alias(libs.plugins.tck.build)
}

buildscript {
    dependencies {
        val version: String by project
        classpath("org.eclipse.dataspacetck.build.tck-build:org.eclipse.dataspacetck.build.tck-build.gradle.plugin:$version")
        classpath("org.eclipse.dataspacetck.build.tck-generator:org.eclipse.dataspacetck.build.tck-generator.gradle.plugin:$version")
    }
}


allprojects {

    apply(plugin = "java-library")
    apply(plugin = "checkstyle")
    apply(plugin = "maven-publish")
    apply(plugin = "signing")
    apply(plugin = "org.eclipse.dataspacetck.build.tck-build")

    configure<TckBuildExtension> {
        pom {
            scmConnection = "https://github.com/eclipse-dataspacetck/dcp-tck.git"
            scmUrl = "scm:git:git@github.com:eclipse-dataspacetck/dcp-tck.git"
            groupId = project.group.toString()
            projectName = project.name
            description = "DCP Technology Compatibility Kit"
            projectUrl = "https://projects.eclipse.org/projects/technology.dataspacetck"
        }
    }

    tasks.test {
        useJUnitPlatform()
        systemProperty("dataspacetck.launcher", "org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher")
    }

    dependencies {
        implementation(rootProject.libs.json.api)
        implementation(rootProject.libs.jackson.databind)
        implementation(rootProject.libs.jackson.jsonp)
        implementation(rootProject.libs.titanium)
        implementation(rootProject.libs.okhttp)
        implementation(rootProject.libs.junit.jupiter)
        implementation(rootProject.libs.junit.platform.engine)
        implementation(rootProject.libs.mockito.core)
        implementation(rootProject.libs.awaitility)
        testImplementation(rootProject.libs.assertj)
    }

}

// needed for running the dash tool
tasks.register("allDependencies", DependencyReportTask::class)

// disallow any errors
checkstyle {
    maxErrors = 0
}

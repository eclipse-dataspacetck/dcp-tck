/*
 *  Copyright (c) 2024 Metaform Systems, Inc.
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

package org.eclipse.dataspacetck.dcp.suite;

import org.eclipse.dataspacetck.core.spi.boot.Monitor;
import org.eclipse.dataspacetck.core.system.ConsoleMonitor;
import org.eclipse.dataspacetck.runtime.TckRuntime;
import org.jetbrains.annotations.NotNull;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import static java.lang.Boolean.parseBoolean;
import static java.util.stream.Collectors.toMap;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_LAUNCHER;
import static org.eclipse.dataspacetck.core.api.system.SystemsConstants.TCK_PREFIX;
import static org.eclipse.dataspacetck.core.system.ConsoleMonitor.ANSI_PROPERTY;
import static org.eclipse.dataspacetck.core.system.ConsoleMonitor.DEBUG_PROPERTY;

/**
 * Boots the DCP test suite.
 */
public class DcpTckSuite {
    private static final String VERSION = "2025.1";
    private static final String CONFIG = "-config";
    private static final String DEFAULT_LAUNCHER = "org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher";
    private static final String DEFAULT_TEST_PACKAGE = "org.eclipse.dataspacetck.dcp.verification"; // will run all tests
    private static final String TCK_TEST_PACKAGE = TCK_PREFIX + ".test.package";

    public static void main(String... args) {
        var properties = readConfig(args);
        if (!properties.containsKey(TCK_LAUNCHER)) {
            properties.put(TCK_LAUNCHER, DEFAULT_LAUNCHER);
        }
        if (properties.containsKey(TCK_TEST_PACKAGE)) {
            properties.put(TCK_TEST_PACKAGE, DEFAULT_TEST_PACKAGE);
        }
        var monitor = createMonitor(properties);
        monitor.enableBold().message("\u001B[1mRunning DCP TCK v" + VERSION + "\u001B[0m").resetMode();
        var result = TckRuntime.Builder.newInstance()
                .properties(properties)
                .addPackage(DEFAULT_TEST_PACKAGE)
                .monitor(monitor)
                .build().execute();


        monitor.resetMode().message("Test run complete");

        if (!result.getFailures().isEmpty()) {
            var failures = result.getFailures().stream()
                    .map(f -> "- " + f.getTestIdentifier().getDisplayName() + " (" + f.getException() + ")")
                    .collect(Collectors.joining("\n"));
            monitor.enableError().message("There were failing tests:\n" + failures);
        }
    }

    @NotNull
    private static Monitor createMonitor(Map<String, String> properties) {
        var ansi = parseBoolean(properties.getOrDefault(ANSI_PROPERTY, "true"));
        var debug = parseBoolean(properties.getOrDefault(DEBUG_PROPERTY, "false"));
        return new ConsoleMonitor(debug, ansi);
    }

    private static Map<String, String> readConfig(String[] args) {
        var fromFile = readConfigFile(args);
        var environment = readEnvironment();

        var config = new HashMap<>(fromFile);
        config.putAll(environment); // potentially overwrites
        return config;
    }

    private static Map<String, String> readEnvironment() {
        // we are only interested in TCK config environment variables

        return System.getenv().entrySet().stream()
                .filter(e -> e.getKey().toLowerCase().startsWith(TCK_PREFIX))
                .map(e -> Map.entry(e.getKey().toLowerCase().replace("_", "."), e.getValue()))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @NotNull
    private static Map<String, String> readConfigFile(String[] args) {
        if (args == null || args.length == 0) {
            return new HashMap<>();
        }
        if (args.length != 2) {
            throw new IllegalArgumentException("Invalid number of arguments: " + args.length);
        }
        if (!CONFIG.equals(args[0])) {
            throw new IllegalArgumentException("Invalid argument: " + args[0]);
        }
        if (!Files.exists(Path.of(args[1]))) {
            System.err.println("The specified configuration file does not exist: " + args[1]);
            return new HashMap<>();
        }
        try (var reader = new FileReader(args[1])) {
            var properties = new Properties();
            properties.load(reader);
            //noinspection unchecked,rawtypes
            return (Map) properties;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

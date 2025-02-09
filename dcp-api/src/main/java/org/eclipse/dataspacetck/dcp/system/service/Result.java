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

package org.eclipse.dataspacetck.dcp.system.service;

/**
 * Result of a service invocation.
 */
public class Result<T> {
    private final T content;
    private final String failure;

    public static Result<Void> success() {
        return new Result<>(null, null);
    }

    public static <T> Result<T> success(T content) {
        return new Result<>(content, null);
    }

    public boolean succeeded() {
        return failure == null;
    }

    public boolean failed() {
        return !succeeded();
    }

    public T getContent() {
        return content;
    }

    public String getFailure() {
        return failure;
    }

    public static <T> Result<T> failure(String failure) {
        return new Result<>(null, failure);
    }

    public <R> R convert() {
        //noinspection unchecked
        return (R) this;
    }

    private Result(T content, String failure) {
        this.content = content;
        this.failure = failure;
    }
}

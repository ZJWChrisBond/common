package com.zjw.common.lang.function;

import java.util.function.Supplier;

/**
 * <p>ExceptionalSupplier interface.</p>
 *
 * @author zjw
 */
@FunctionalInterface
public interface ExceptionalSupplier<T> {

    /**
     * See {@link Supplier#get()}
     */
    @SuppressWarnings("java:S112")
    T get() throws Exception;

}
package com.zjw.common.lang.function;


/**
 * <p>ExceptionalRunnable interface.</p>
 *
 * @author zjw
 */
@FunctionalInterface
public interface ExceptionalRunnable {

    /**
     * {@link Runnable#run()}
     */
    @SuppressWarnings("java:S112")
    void run() throws Exception;

}

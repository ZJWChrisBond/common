package com.zjw.common.lang;

import com.zjw.common.lang.function.ExceptionalRunnable;
import com.zjw.common.lang.function.ExceptionalSupplier;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.logging.LogLevel;

/**
 * <p>Try class.</p>
 *
 * @author zjw
 */
public class Try {

    private static final Logger logger = LoggerFactory.getLogger(Try.class);

    private static final Runner NOLOG = new Runner(null);
    private static final Runner DEBUG = new Runner(LogLevel.DEBUG);
    private static final Runner ERROR = new Runner(LogLevel.ERROR);
    private static final Runner WARN = new Runner(LogLevel.WARN);

    private Try() {

    }

    /**
     * Executes the function and rethrow the checked exception as unchecked.
     */
    public static <T> T rethrow(ExceptionalSupplier<T> func) {
        return NOLOG.rethrow(func);
    }

    /**
     * Executes the function and rethrow the checked exception as unchecked.
     */
    public static <T> T rethrow(String message, ExceptionalSupplier<T> func) {
        return NOLOG.rethrow(message, func);
    }

    /**
     * Executes the function and rethrow the checked exception as unchecked.
     */
    public static void rethrow(ExceptionalRunnable func) {
        NOLOG.rethrow(func);
    }

    /**
     * Executes the function and rethrow the checked exception as unchecked.
     */
    public static void rethrow(String message, ExceptionalRunnable func) {
        NOLOG.rethrow(message, func);
    }

    /**
     * Executes the function and log error if any exception thrown.
     */
    public static <T> T error(T defaultValue, ExceptionalSupplier<T> func) {
        return ERROR.log(defaultValue, func);
    }

    /**
     * Executes the function and log error if any exception thrown.
     */
    public static void error(ExceptionalRunnable func) {
        ERROR.log(func);
    }

    /**
     * Executes the function and log warning if any exception thrown.
     */
    public static <T> T warning(T defaultValue, ExceptionalSupplier<T> func) {
        return WARN.log(defaultValue, func);
    }

    /**
     * Executes the function and log warning if any exception thrown.
     */
    public static void warning(ExceptionalRunnable func) {
        WARN.log(func);
    }

    /**
     * Executes the function and log debug if any exception thrown.
     */
    public static <T> T debug(T defaultValue, ExceptionalSupplier<T> func) {
        return DEBUG.log(defaultValue, func);
    }

    /**
     * Executes the function and log debug if any exception thrown.
     */
    public static void debug(ExceptionalRunnable func) {
        DEBUG.log(func);
    }

    /**
     * The runner class
     */
    static final class Runner {

        private final LogLevel logLevel;

        private Runner(LogLevel logLevel) {
            this.logLevel = logLevel;
        }

        public <T> T log(T defaultValue, ExceptionalSupplier<T> func) {
            try {
                return func.get();
            } catch (Exception e) {
                log(e);
                return defaultValue;
            }
        }

        /**
         * Run the function and catching all exceptions
         */
        public void log(ExceptionalRunnable func) {
            try {
                func.run();
            } catch (Exception e) {
                log(e);
            }
        }

        /**
         * Run the function with throwing {@link RuntimeException} if exception thrown.
         */
        public <T> T rethrow(ExceptionalSupplier<T> func) {
            return rethrow(null, func);
        }

        /**
         * Run the function with throwing {@link RuntimeException} if exception thrown.
         */
        public <T> T rethrow(String message, ExceptionalSupplier<T> func) {
            try {
                return func.get();
            } catch (Exception e) {
                log(e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    if (!StringUtils.isEmpty(message)) {
                        throw new IllegalStateException(message, e);
                    } else {
                        throw new IllegalStateException(e);
                    }
                }
            }
        }

        /**
         * Run the function with throwing {@link IllegalStateException} if exception thrown.
         */
        public void rethrow(ExceptionalRunnable func) {
            rethrow(null, func);
        }

        /**
         * Run the function with throwing {@link IllegalStateException} if exception thrown.
         */
        public void rethrow(String message, ExceptionalRunnable func) {
            try {
                func.run();
            } catch (Exception e) {
                log(e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    if (!StringUtils.isEmpty(message)) {
                        throw new IllegalStateException(message, e);
                    } else {
                        throw new IllegalStateException(e);
                    }
                }
            }
        }

        private void log(Exception e) {
            if (null == logLevel) {
                return;
            }

            if (logLevel == LogLevel.ERROR) {
                logger.error(e.getMessage(), e);
                return;
            }

            if (logLevel == LogLevel.WARN) {
                logger.warn(e.getMessage(), e);
            }

            logger.debug(e.getMessage(), e);
        }
    }
}

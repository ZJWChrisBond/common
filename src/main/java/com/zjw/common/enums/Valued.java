package com.zjw.common.enums;

import org.springframework.lang.Nullable;

/**
 * <p>Valued interface.</p>
 *
 * @author zjw
 */
public interface Valued<T> {

    /**
     * Returns the value.
     */
    @Nullable
    T getValue();

}

package com.zjw.common.utils.time;

import org.apache.commons.lang3.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

/**
 * Simple utils for date and time.
 *
 * @author zjw
 */
public class DateTimes {

    public static final DateTimeFormatter TIMESTAMP_INSTANT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSX");

    /**
     * The ISO data-time formatter that formats or parses a date-time with an offset, such as
     * '2023-05-24T10:02:34+0000'.
     */
    public static final DateTimeFormatter ISO_OFFSET_X_DATE_TIME = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .append(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            .parseLenient()
            .appendOffset("+HHMM", "+0000")
            .parseStrict()
            .toFormatter();

    private DateTimes() {

    }

    /**
     * Parse {@link String} to {@link Timestamp}.
     */
    public static Timestamp parseTimestamp(String value) {
        if (value.contains("T")) {
            int index = value.indexOf('+');
            if (index > 0) {
                if (value.indexOf(':', index) > 0) {
                    return new Timestamp(
                            DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(value, Instant::from).toEpochMilli());
                }
                return new Timestamp(ISO_OFFSET_X_DATE_TIME.parse(value, Instant::from).toEpochMilli());
            }
            return new Timestamp(DateTimeFormatter.ISO_INSTANT.parse(value, Instant::from).toEpochMilli());
        } else if (value.contains("+")) {
            return new Timestamp(TIMESTAMP_INSTANT.parse(value, Instant::from).toEpochMilli());
        } else {
            return Timestamp.valueOf(value);
        }
    }

    /**
     * Parse {@link String} to {@link LocalDateTime}.
     */
    public static LocalDateTime parseLocalDateTime(String value) {
        if (value.contains("Z") || value.contains("+")) {
            return DateTimes.parseTimestamp(value).toLocalDateTime();
        }
        return LocalDateTime.parse(value);
    }

    /**
     * Parse {@link String} to {@link LocalDate}.
     */

    public LocalDate convert(String source) {
        if (StringUtils.isBlank(source)) {
            return null;
        }
        if (source.contains("T") || source.contains("+")) {
            Timestamp timestamp = DateTimes.parseTimestamp(source);
            LocalDateTime localDateTime = timestamp.toLocalDateTime();
            return localDateTime.toLocalDate();
        } else {
            return LocalDate.parse(source, DateTimeFormatter.ISO_DATE);
        }
    }

}

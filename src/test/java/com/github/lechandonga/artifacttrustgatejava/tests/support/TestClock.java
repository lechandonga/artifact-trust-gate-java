package com.github.lechandonga.artifacttrustgatejava.tests.support;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * 测试用可控时钟：可以定格、推进，用于验证吊销生效时间、证明有效期等边界。
 */
public class TestClock extends Clock {

    private Instant instant;
    private final ZoneId zone = ZoneOffset.UTC;

    public TestClock(Instant initial) {
        this.instant = initial;
    }

    public void setInstant(Instant instant) {
        this.instant = instant;
    }

    public void advanceSeconds(long seconds) {
        this.instant = instant.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return instant;
    }
}

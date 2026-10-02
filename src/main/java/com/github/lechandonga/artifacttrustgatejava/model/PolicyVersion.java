package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;
import java.util.List;

/**
 * 策略版本：版本不可变、仅追加，保证历史判定可追溯、可复现。
 */
public record PolicyVersion(
        int version,
        Instant createdAt,
        List<PolicyRule> rules
) {
}

package com.github.lechandonga.artifacttrustgatejava.model;

/**
 * 策略规则：按 rules 列表顺序匹配，first-match-wins。
 * matchKeyId 为空表示默认规则（default）。
 */
public record PolicyRule(
        String ruleId,
        String matchKeyId,
        boolean allow,
        String message
) {
}

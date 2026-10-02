package com.github.lechandonga.artifacttrustgatejava.policy;

import java.util.List;

/**
 * @param version       策略版本（如 "1"、"2"），文件名 policy-v{version}.json
 * @param effectiveFrom 生效时间（epoch millis，含）
 * @param defaultEffect 无规则命中时的兜底动作（建议 DENY）
 * @param rules         有序规则，自上而下首条命中即生效
 */
public record PolicyDocument(String version, long effectiveFrom,
                             String defaultEffect, List<Rule> rules) {

    /**
     * 一条规则：当 all 中所有约束都满足时命中；all 为空表示兜底规则。
     * 支持的约束键：
     *   issuerEquals        签发者等于
     *   keyIdIn             keyId 属于集合
     *   artifactTypeEquals  制品 type 字段等于
     *   maxArtifactSize     制品规范化字节数上限
     *   requireSigned       必须携带有效签名（准入服务只对已通过签名校验的制品评估）
     */
    public record Rule(String name, String effect, List<Constraint> all) {
    }

    public record Constraint(String constraint, Object expected) {
    }
}

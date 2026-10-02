package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;

/**
 * 准入结论。包含命中规则、固定的策略/密钥快照版本，
 * 以及是否复用了已有审计记录（幂等）。
 */
public record DecisionResult(
        String submissionId,
        DecisionCode code,
        boolean allowed,
        String reason,
        String artifactDigest,
        String attestationId,
        String keyId,
        String matchedRuleId,
        int policyVersion,
        int keyBookVersion,
        Instant evaluationTime,
        Instant decisionTime,
        boolean reusedAuditRecord
) {
}

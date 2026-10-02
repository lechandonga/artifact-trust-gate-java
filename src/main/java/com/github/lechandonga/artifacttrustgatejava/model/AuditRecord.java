package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;

/**
 * 审计记录：一次判定一条；同一自然键重复提交只保留第一条。
 */
public record AuditRecord(
        String submissionId,
        String idempotencyKey,
        DecisionResult result,
        Instant recordedAt
) {
}

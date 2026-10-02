package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;

/**
 * 吊销记录（仅追加，不可删除）。
 * revokedAt 为吊销生效时间，允许定时吊销（未来时间）；
 * recordCreatedAt 为登记时间，用于拒绝倒填日期（backdating）。
 */
public record Revocation(
        String keyId,
        Instant revokedAt,
        Instant recordCreatedAt,
        String reason
) {
}

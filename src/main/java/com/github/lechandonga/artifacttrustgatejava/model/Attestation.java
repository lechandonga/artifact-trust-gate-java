package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;

/**
 * 证明（attestation）：对制品指纹的签名声明。
 * 字段固定，签名覆盖规范化后的证明载荷（不含 signature 字段）。
 */
public record Attestation(
        String attestationId,
        String subjectDigest,
        String keyId,
        Instant issuedAt,
        Instant expiresAt,
        String signature
) {
}

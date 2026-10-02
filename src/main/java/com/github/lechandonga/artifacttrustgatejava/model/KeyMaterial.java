package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;

/**
 * 本地密钥材料。私钥仅用于本地演示签发；公钥用于验签。
 * 吊销状态不放在密钥本身，而由独立的、仅追加的吊销账本决定，
 * 这样历史制品的判定不会被后来的记录改写（按快照版本复现）。
 */
public record KeyMaterial(
        String keyId,
        String publicKeyPem,
        String privateKeyPem,
        Instant createdAt,
        String replacedBy
) {
}

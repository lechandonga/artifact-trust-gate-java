package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;
import java.util.List;

/**
 * 密钥状态快照：version 与吊销账本追加后的条目数绑定。
 * 判定时固定快照版本，历史判定即按当时的密钥状态稳定复现。
 */
public record KeyBookSnapshot(
        int version,
        Instant createdAt,
        List<Revocation> revocations
) {
}

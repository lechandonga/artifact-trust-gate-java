package com.github.lechandonga.artifacttrustgatejava.service;

import com.github.lechandonga.artifacttrustgatejava.model.KeyState;
import com.github.lechandonga.artifacttrustgatejava.store.KeyMaterial;

/**
 * 密钥状态判断（时间点语义）：
 *  - NOT_YET_VALID：判断时间点早于密钥生效时间
 *  - REVOKED：密钥已吊销且吊销生效时间 <= 判断时间点（吊销只对未来生效）
 *  - EXPIRED：密钥有有效期且判断时间点晚于到期时间
 *  - ACTIVE：其余情况
 *
 * 吊销携带“生效时间”，因此：
 *   吊销生效前签发、且证明仍在有效期内的历史制品不会被追溯失效；
 *   吊销生效后不允许再用同一密钥签发新证明。
 */
public final class KeyStateEvaluator {

    private KeyStateEvaluator() {
    }

    public static KeyState stateAt(KeyMaterial key, long at) {
        if (at < key.validFrom()) {
            return KeyState.NOT_YET_VALID;
        }
        if (key.revokedAt() != null && key.revokedAt() <= at) {
            return KeyState.REVOKED;
        }
        if (key.validUntil() != null && at > key.validUntil()) {
            return KeyState.EXPIRED;
        }
        return KeyState.ACTIVE;
    }
}

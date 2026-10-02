package com.github.lechandonga.artifacttrustgatejava.store;

/**
 * @param keyId       密钥 ID
 * @param publicKey   X.509 SubjectPublicKeyInfo，Base64
 * @param privateKey  PKCS#8，Base64；仅本地签发演示使用，校验服务只用公钥
 * @param validFrom   密钥生效时间（epoch millis，含）
 * @param validUntil  密钥到期时间（epoch millis，含）
 * @param revokedAt   吊销生效时间（epoch millis）；null 表示未吊销
 * @param revokedReason 吊销原因
 */
public record KeyMaterial(String keyId, String publicKey, String privateKey,
                          long validFrom, Long validUntil,
                          Long revokedAt, String revokedReason) {

    public KeyMaterial withRevocation(long at, String reason) {
        return new KeyMaterial(keyId, publicKey, privateKey, validFrom, validUntil, at, reason);
    }
}

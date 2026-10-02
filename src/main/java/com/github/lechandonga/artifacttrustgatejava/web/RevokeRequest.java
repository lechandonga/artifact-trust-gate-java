package com.github.lechandonga.artifacttrustgatejava.web;

/**
 * @param keyId     要吊销的密钥
 * @param revokedAt 吊销生效时间（epoch millis）；null 表示立即生效
 * @param reason    吊销原因
 */
public record RevokeRequest(String keyId, Long revokedAt, String reason) {
}

package com.github.lechandonga.artifacttrustgatejava.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class Digests {

    private Digests() {
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 制品指纹：对规范化字节做 SHA-256。
     */
    public static String artifactDigest(String contentJson) {
        return sha256Hex(JsonCanonicalizer.canonicalize(contentJson));
    }
}

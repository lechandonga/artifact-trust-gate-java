package com.github.lechandonga.artifacttrustgatejava.crypto;

public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = DIGITS[v >>> 4];
            out[i * 2 + 1] = DIGITS[v & 0x0F];
        }
        return new String(out);
    }

    public static byte[] decode(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("十六进制串长度必须为偶数");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("非法十六进制字符");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}

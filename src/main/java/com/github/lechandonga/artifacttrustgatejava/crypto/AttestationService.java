package com.github.lechandonga.artifacttrustgatejava.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * EC (secp256r1 / SHA256withECDSA, IEEE-P1363 定长编码) 签名工具。
 *
 * 被签的载荷固定为证明中下列字段的规范化 JSON：
 * keyId, artifactDigest, notBefore, notAfter, issuedAt, issuer。
 */
@Component
public class AttestationService {

    public static final String SIGN_ALGORITHM = "SHA256withECDSA";
    public static final String KEY_ALGORITHM = "EC";

    private final ObjectMapper mapper = new ObjectMapper();

    public byte[] signaturePayload(Map<String, Object> attestationFields) {
        Map<String, Object> covered = new LinkedHashMap<>();
        covered.put("keyId", attestationFields.get("keyId"));
        covered.put("artifactDigest", attestationFields.get("artifactDigest"));
        covered.put("notBefore", attestationFields.get("notBefore"));
        covered.put("notAfter", attestationFields.get("notAfter"));
        covered.put("issuedAt", attestationFields.get("issuedAt"));
        covered.put("issuer", attestationFields.get("issuer"));
        return JsonCanonicalizer.canonicalize(writeJson(covered));
    }

    public String sign(byte[] payload, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(payload);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new IllegalStateException("签名失败", e);
        }
    }

    public boolean verify(byte[] payload, String signatureBase64, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(payload);
            return signature.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (Exception e) {
            return false;
        }
    }

    public PublicKey loadPublicKey(String base64) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64));
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("公钥材料损坏", e);
        }
    }

    public PrivateKey loadPrivateKey(String base64) {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64));
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("私钥材料损坏", e);
        }
    }

    public String utf8(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    private String writeJson(Map<String, Object> map) {
        try {
            return mapper.writeValueAsString(map);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}

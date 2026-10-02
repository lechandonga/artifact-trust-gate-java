package com.github.lechandonga.artifacttrustgatejava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.crypto.AttestationService;
import com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer;
import com.github.lechandonga.artifacttrustgatejava.model.KeyState;
import com.github.lechandonga.artifacttrustgatejava.store.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.store.LocalGateStore;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 本地“签发端”：用模拟私钥为制品生成证明。
 * 签发时强制校验密钥状态——吊销生效后、未生效或已过期的密钥一律拒绝签发。
 */
@Service
public class AttestationIssuer {

    private final LocalGateStore store;
    private final AttestationService signatures;
    private final ObjectMapper mapper = new ObjectMapper();

    public AttestationIssuer(LocalGateStore store, AttestationService signatures) {
        this.store = store;
        this.signatures = signatures;
    }

    public String issue(String keyId, String artifactJson, String issuer,
                        long issuedAt, long notBefore, long notAfter) {
        KeyMaterial key = store.findKey(keyId)
                .orElseThrow(() -> new IllegalArgumentException("密钥不存在: " + keyId));
        KeyState state = KeyStateEvaluator.stateAt(key, issuedAt);
        if (state != KeyState.ACTIVE) {
            throw new IllegalStateException("密钥在签发时间点状态为 " + state
                    + "，不允许签发（keyId=" + keyId + "）");
        }
        if (issuedAt < notBefore || issuedAt > notAfter) {
            throw new IllegalArgumentException("签发时间必须落在证明有效期内");
        }

        String digest = JsonCanonicalizer.sha256Hex(artifactJson);
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("keyId", keyId);
        fields.put("artifactDigest", digest);
        fields.put("notBefore", notBefore);
        fields.put("notAfter", notAfter);
        fields.put("issuedAt", issuedAt);
        fields.put("issuer", issuer);
        String signature = signatures.sign(signatures.signaturePayload(fields),
                signatures.loadPrivateKey(key.privateKey()));

        Map<String, Object> attestation = new LinkedHashMap<>(fields);
        attestation.put("algorithm", AttestationService.SIGN_ALGORITHM);
        attestation.put("signature", signature);
        try {
            return mapper.writeValueAsString(attestation);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized void revoke(String keyId, long revokedAt, String reason) {
        KeyMaterial key = store.findKey(keyId)
                .orElseThrow(() -> new IllegalArgumentException("密钥不存在: " + keyId));
        if (key.revokedAt() != null) {
            throw new IllegalStateException("密钥已吊销: " + keyId);
        }
        store.putKey(key.withRevocation(revokedAt, reason));
    }
}

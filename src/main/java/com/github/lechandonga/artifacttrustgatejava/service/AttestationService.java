package com.github.lechandonga.artifacttrustgatejava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer;
import com.github.lechandonga.artifacttrustgatejava.crypto.RsaSignatureService;
import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionCode;
import com.github.lechandonga.artifacttrustgatejava.model.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.model.Revocation;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.store.KeyStore;
import com.github.lechandonga.artifacttrustgatejava.store.RevocationLedger;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * 证明签发与载荷构造。签名载荷是证明字段（不含 signature）的规范化 JSON，
 * 与制品内容使用同一套规范化规则。
 */
@Service
public class AttestationService {

    private final ObjectMapper mapper;
    private final KeyStore keyStore;
    private final RevocationLedger revocationLedger;
    private final RsaSignatureService rsa;
    private final Clock clock;

    public AttestationService(ObjectMapper mapper, KeyStore keyStore, RevocationLedger revocationLedger,
                              RsaSignatureService rsa, Clock clock) {
        this.mapper = mapper;
        this.keyStore = keyStore;
        this.revocationLedger = revocationLedger;
        this.rsa = rsa;
        this.clock = clock;
    }

    public Attestation issue(String keyId, String subjectDigest, Duration ttl) {
        Instant now = Instant.now(clock);
        KeyMaterial key = keyStore.find(keyId)
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_KEY_UNKNOWN,
                        "密钥不存在: " + keyId));

        // 吊销生效后不得再用同一密钥签发（含未来定时吊销未生效时尚可签发）
        revocationLedger.findAll().stream()
                .filter(r -> r.keyId().equals(keyId))
                .filter(r -> !r.revokedAt().isAfter(now))
                .findAny()
                .ifPresent(r -> {
                    throw new ServiceException(DecisionCode.REJECT_KEY_REVOKED,
                            "密钥已于 " + r.revokedAt() + " 吊销生效，不能再签发证明: " + keyId);
                });

        return sign(key, subjectDigest, now, now.plus(ttl));
    }

    /**
     * 用指定时间点签发（测试/离线补签场景）：仍会执行“签发时刻密钥未被吊销”的约束，
     * 调用方可通过可控时钟模拟吊销生效前后的真实签发行为。
     */
    public Attestation issueAt(String keyId, String subjectDigest, Instant issuedAt, Duration ttl) {
        KeyMaterial key = keyStore.find(keyId)
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_KEY_UNKNOWN,
                        "密钥不存在: " + keyId));
        revocationLedger.findAll().stream()
                .filter(r -> r.keyId().equals(keyId))
                .filter(r -> !r.revokedAt().isAfter(issuedAt))
                .findAny()
                .ifPresent(r -> {
                    throw new ServiceException(DecisionCode.REJECT_KEY_REVOKED,
                            "密钥在签发时刻 " + issuedAt + " 已因吊销 " + r.revokedAt() + " 生效");
                });
        return sign(key, subjectDigest, issuedAt, issuedAt.plus(ttl));
    }

    private Attestation sign(KeyMaterial key, String subjectDigest, Instant issuedAt, Instant expiresAt) {
        Attestation unsigned = new Attestation(
                "att-" + UUID.randomUUID(), subjectDigest, key.keyId(), issuedAt, expiresAt, null);
        byte[] payload = signingPayload(unsigned);
        PrivateKey privateKey = rsa.parsePrivateKey(key.privateKeyPem());
        String signature = rsa.sign(payload, privateKey);
        return new Attestation(unsigned.attestationId(), unsigned.subjectDigest(), unsigned.keyId(),
                unsigned.issuedAt(), unsigned.expiresAt(), signature);
    }

    /**
     * 仅用于测试/离线场景：绕过“签发时刻吊销”约束直接签名，
     * 用来模拟密钥吊销后留存私钥仍被越权使用——此时签名本身合法，
     * 必须由验签阶段的吊销语义（issuedAt &gt;= revokedAt）识别并拒绝。
     */
    public Attestation issueAtBypass(String keyId, String subjectDigest, Instant issuedAt, Duration ttl) {
        KeyMaterial key = keyStore.find(keyId)
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_KEY_UNKNOWN,
                        "密钥不存在: " + keyId));
        return sign(key, subjectDigest, issuedAt, issuedAt.plus(ttl));
    }

    public byte[] signingPayload(Attestation a) {
        ObjectNode node = mapper.createObjectNode();
        node.put("attestationId", a.attestationId());
        node.put("subjectDigest", a.subjectDigest());
        node.put("keyId", a.keyId());
        node.put("issuedAt", a.issuedAt().toString());
        node.put("expiresAt", a.expiresAt().toString());
        return JsonCanonicalizer.canonicalize(node.toString());
    }

    public String payloadText(Attestation a) {
        return new String(signingPayload(a), StandardCharsets.UTF_8);
    }

    /**
     * 判断密钥在吊销账本快照下，对签发于 issuedAt 的证明是否已因吊销失效。
     * 语义：吊销在 revokedAt 生效；生效前签发的证明在自身有效期内仍有效，
     * 只有“吊销生效后仍用该密钥签发”的证明才判定吊销失效。
     */
    public Revocation findInvalidatingRevocation(String keyId, Instant issuedAt,
                                                 java.util.List<Revocation> revocations) {
        return revocations.stream()
                .filter(r -> r.keyId().equals(keyId))
                .filter(r -> !r.revokedAt().isAfter(issuedAt))
                .findFirst()
                .orElse(null);
    }
}

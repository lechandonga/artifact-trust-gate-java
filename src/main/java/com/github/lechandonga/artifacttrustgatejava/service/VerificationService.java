package com.github.lechandonga.artifacttrustgatejava.service;

import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.crypto.RsaSignatureService;
import com.github.lechandonga.artifacttrustgatejava.model.ArtifactRef;
import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionCode;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
import com.github.lechandonga.artifacttrustgatejava.model.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.model.Revocation;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.store.KeyStore;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Instant;

/**
 * 证明校验。各类失败原因严格区分，按固定顺序短路：
 * 材料不完整 → 密钥未知 → 内容指纹不符(篡改) → 签名不匹配 →
 * 证明时间无效(过期/未来签发) → 密钥吊销失效。
 */
@Service
public class VerificationService {

    private final KeyStore keyStore;
    private final RsaSignatureService rsa;
    private final AttestationService attestationService;

    public VerificationService(KeyStore keyStore, RsaSignatureService rsa,
                               AttestationService attestationService) {
        this.keyStore = keyStore;
        this.rsa = rsa;
        this.attestationService = attestationService;
    }

    public record Verified(String artifactDigest, KeyMaterial key, Attestation attestation) {
    }

    public Verified verify(ArtifactRef artifact, Attestation attestation,
                           KeyBookSnapshot snapshot, Instant evaluationTime) {
        if (artifact == null || artifact.contentJson() == null || artifact.contentJson().isBlank()) {
            throw new ServiceException(DecisionCode.REJECT_UNKNOWN_ARTIFACT, "缺少制品内容");
        }
        String artifactDigest;
        try {
            artifactDigest = Digests.artifactDigest(artifact.contentJson());
        } catch (IllegalArgumentException e) {
            throw new ServiceException(DecisionCode.REJECT_UNKNOWN_ARTIFACT,
                    "制品不是合法 JSON，无法计算指纹: " + e.getMessage());
        }

        if (attestation == null) {
            throw new ServiceException(DecisionCode.REJECT_ATTESTATION_MISSING,
                    "签名材料不完整：缺少证明(attestation)");
        }
        if (attestation.signature() == null || attestation.signature().isBlank()) {
            throw new ServiceException(DecisionCode.REJECT_SIGNATURE_MISSING,
                    "签名材料不完整：证明缺少 signature 字段");
        }
        KeyMaterial key = keyStore.find(attestation.keyId())
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_KEY_UNKNOWN,
                        "签名密钥未登记/已轮换下线: " + attestation.keyId()));

        if (!artifactDigest.equals(attestation.subjectDigest())) {
            throw new ServiceException(DecisionCode.REJECT_CONTENT_DIGEST_MISMATCH,
                    "制品内容指纹与证明声明不一致，内容疑似被篡改: 实际=" + artifactDigest
                            + ", 声明=" + attestation.subjectDigest());
        }

        PublicKey publicKey = rsa.parsePublicKey(key.publicKeyPem());
        boolean valid = rsa.verify(attestationService.signingPayload(attestation),
                attestation.signature(), publicKey);
        if (!valid) {
            throw new ServiceException(DecisionCode.REJECT_SIGNATURE_INVALID,
                    "签名验证不通过：签名与证明载荷/公钥不匹配");
        }

        if (attestation.issuedAt().isAfter(evaluationTime)) {
            throw new ServiceException(DecisionCode.REJECT_ATTESTATION_EXPIRED,
                    "证明签发时间晚于评估时间（未来签发）: issuedAt=" + attestation.issuedAt());
        }
        if (!evaluationTime.isBefore(attestation.expiresAt())) {
            throw new ServiceException(DecisionCode.REJECT_ATTESTATION_EXPIRED,
                    "证明已过有效期: expiresAt=" + attestation.expiresAt()
                            + ", evaluationTime=" + evaluationTime);
        }

        Revocation invalidating = attestationService.findInvalidatingRevocation(
                attestation.keyId(), attestation.issuedAt(), snapshot.revocations());
        if (invalidating != null) {
            throw new ServiceException(DecisionCode.REJECT_KEY_REVOKED,
                    "密钥吊销在证明签发前/当时已生效: revokedAt=" + invalidating.revokedAt()
                            + ", issuedAt=" + attestation.issuedAt());
        }

        return new Verified(artifactDigest, key, attestation);
    }
}

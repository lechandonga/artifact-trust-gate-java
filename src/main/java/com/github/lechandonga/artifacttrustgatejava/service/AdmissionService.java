package com.github.lechandonga.artifacttrustgatejava.service;

import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.model.AdmissionRequest;
import com.github.lechandonga.artifacttrustgatejava.model.AuditRecord;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionCode;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionResult;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyRule;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyVersion;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.store.AuditStore;
import com.github.lechandonga.artifacttrustgatejava.store.RevocationLedger;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * 准入编排：
 * 1. 固定评估上下文（评估时间、策略版本、密钥状态快照版本）；
 * 2. 校验证明（签名/内容/时效/吊销）；
 * 3. 按固定策略版本评估命中规则；
 * 4. 按自然键幂等写审计——重复提交返回同一结论、不产生重复审计。
 * 并发上使用基于自然键哈希的分段锁，不同键并行、同键串行，
 * 结论只从审计存储回读，避免缓存串数据与判定互相覆盖。
 */
@Service
public class AdmissionService {

    private static final int STRIPES = 16;

    private final VerificationService verificationService;
    private final PolicyService policyService;
    private final RevocationLedger revocationLedger;
    private final AuditStore auditStore;
    private final Clock clock;
    private final ObjectMapper mapper;

    @SuppressWarnings("unchecked")
    private final Object[] stripeLocks = java.util.stream.IntStream.range(0, STRIPES)
            .mapToObj(i -> new Object())
            .toArray(Object[]::new);

    public AdmissionService(VerificationService verificationService, PolicyService policyService,
                            RevocationLedger revocationLedger, AuditStore auditStore,
                            ObjectMapper mapper, Clock clock) {
        this.verificationService = verificationService;
        this.policyService = policyService;
        this.revocationLedger = revocationLedger;
        this.auditStore = auditStore;
        this.clock = clock;
        this.mapper = mapper;
    }

    public DecisionResult submit(AdmissionRequest request) {
        if (request == null || request.artifact() == null) {
            throw new ServiceException(DecisionCode.REJECT_BAD_REQUEST, "请求缺少 artifact");
        }
        Instant now = Instant.now(clock);
        Instant evaluationTime = request.evaluationTime() != null ? request.evaluationTime() : now;

        PolicyVersion policy = policyService.resolve(request.policyVersion());
        KeyBookSnapshot snapshot = resolveSnapshot(request.keyBookVersion(), evaluationTime);

        String digest = safeArtifactDigest(request);
        // 幂等键中使用证明全字段指纹（含 signature、有效期）：
        // 缺签名、换签名、改载荷等任何材料差异都会形成不同的键，避免错误复用旧结论。
        String attestationFingerprint = attestationFingerprint(request);
        // 未显式指定评估时间时用固定符号 LATEST：同一策略/快照版本内重复提交即复用同一结论；
        // 只有显式历史时刻、新策略版本或新密钥快照版本才形成新的判定上下文。
        String evaluationTimeKey = request.evaluationTime() != null
                ? request.evaluationTime().toString() : "LATEST";
        String idempotencyKey = buildIdempotencyKey(digest, attestationFingerprint, evaluationTimeKey,
                policy.version(), snapshot.version());

        // 快速路径：已判定过直接返回历史结论，保证重复提交完全一致
        var existing = auditStore.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            DecisionResult old = existing.get().result();
            return copyWithReuse(old, true);
        }

        Object lock = stripeLocks[Math.floorMod(idempotencyKey.hashCode(), STRIPES)];
        synchronized (lock) {
            var raced = auditStore.findByIdempotencyKey(idempotencyKey);
            if (raced.isPresent()) {
                return copyWithReuse(raced.get().result(), true);
            }

            DecisionResult result = evaluate(request, evaluationTime, policy, snapshot, digest);
            AuditRecord record = new AuditRecord(UUID.randomUUID().toString(),
                    idempotencyKey, result, Instant.now(clock));
            auditStore.appendIfAbsent(record);
            return result;
        }
    }

    private KeyBookSnapshot resolveSnapshot(Integer requested, Instant evaluationTime) {
        if (requested != null) {
            KeyBookSnapshot snapshot = revocationLedger.snapshotAt(requested);
            if (snapshot == null) {
                throw new ServiceException(DecisionCode.REJECT_KEYBOOK_VERSION_UNKNOWN,
                        "密钥状态快照版本不存在: v" + requested + "（0 表示无任何吊销记录的初始快照）");
            }
            return snapshot;
        }
        return revocationLedger.latestSnapshot(Instant.now(clock));
    }

    private DecisionResult evaluate(AdmissionRequest request, Instant evaluationTime,
                                    PolicyVersion policy, KeyBookSnapshot snapshot,
                                    String digestHint) {
        String artifactDigest = digestHint;
        String keyId = request.attestation() != null ? request.attestation().keyId() : null;
        String attId = request.attestation() != null ? request.attestation().attestationId() : null;

        try {
            VerificationService.Verified verified = verificationService.verify(
                    request.artifact(), request.attestation(), snapshot, evaluationTime);
            artifactDigest = verified.artifactDigest();
            keyId = verified.key().keyId();
            attId = verified.attestation().attestationId();

            PolicyService.Match match = policyService.evaluate(policy, keyId);
            PolicyRule rule = match.rule();
            DecisionCode code = match.allowed() ? DecisionCode.ALLOW : DecisionCode.REJECT_POLICY_DENY;
            return new DecisionResult(UUID.randomUUID().toString(), code, match.allowed(),
                    match.allowed() ? rule.message() : "策略拒绝: " + rule.message(),
                    artifactDigest, attId, keyId, rule.ruleId(), policy.version(),
                    snapshot.version(), evaluationTime, Instant.now(clock), false);
        } catch (ServiceException e) {
            return new DecisionResult(UUID.randomUUID().toString(), e.code(), false,
                    e.getMessage(), artifactDigest, attId, keyId, null, policy.version(),
                    snapshot.version(), evaluationTime, Instant.now(clock), false);
        }
    }

    private String safeArtifactDigest(AdmissionRequest request) {
        try {
            return Digests.artifactDigest(request.artifact().contentJson());
        } catch (RuntimeException e) {
            // 非法 JSON 无法算指纹时用原始字节指纹兜底，幂等键仍稳定
            return "raw:" + Digests.sha256Hex(
                    String.valueOf(request.artifact().contentJson()).getBytes(StandardCharsets.UTF_8));
        }
    }

    private String attestationFingerprint(AdmissionRequest request) {
        if (request.attestation() == null) {
            return "none";
        }
        try {
            String json = mapper.writeValueAsString(request.attestation());
            return com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer
                    .canonicalString(json);
        } catch (Exception e) {
            throw new ServiceException(DecisionCode.REJECT_BAD_REQUEST, "证明序列化失败: " + e.getMessage());
        }
    }

    private String buildIdempotencyKey(String digest, String attestationFingerprint,
                                       String evaluationTimeKey, int policyVersion, int keyBookVersion) {
        String raw = String.join("|",
                nullSafe(digest), Digests.sha256Hex(nullSafe(attestationFingerprint)),
                evaluationTimeKey, Integer.toString(policyVersion),
                Integer.toString(keyBookVersion));
        return Digests.sha256Hex(raw);
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private DecisionResult copyWithReuse(DecisionResult r, boolean reused) {
        return new DecisionResult(r.submissionId(), r.code(), r.allowed(), r.reason(),
                r.artifactDigest(), r.attestationId(), r.keyId(), r.matchedRuleId(),
                r.policyVersion(), r.keyBookVersion(), r.evaluationTime(), r.decisionTime(), reused);
    }
}

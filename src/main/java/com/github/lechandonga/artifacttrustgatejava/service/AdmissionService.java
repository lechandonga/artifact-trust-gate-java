package com.github.lechandonga.artifacttrustgatejava.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.crypto.AttestationService;
import com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer;
import com.github.lechandonga.artifacttrustgatejava.model.DenyReason;
import com.github.lechandonga.artifacttrustgatejava.model.KeyState;
import com.github.lechandonga.artifacttrustgatejava.policy.PolicyDocument;
import com.github.lechandonga.artifacttrustgatejava.policy.PolicyEngine;
import com.github.lechandonga.artifacttrustgatejava.store.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.store.LocalGateStore;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionDecision;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final LocalGateStore store;
    private final AttestationService signatures;
    private final PolicyEngine policyEngine;
    private final ObjectMapper mapper = new ObjectMapper();

    /** 同一 requestId 的在途并发请求在此串行化，杜绝互相覆盖/缓存串数据。 */
    private final ConcurrentHashMap<String, Object> inflightLocks = new ConcurrentHashMap<>();

    public AdmissionService(LocalGateStore store, AttestationService signatures,
                            PolicyEngine policyEngine) {
        this.store = store;
        this.signatures = signatures;
        this.policyEngine = policyEngine;
    }

    @SuppressWarnings("unchecked")
    public AdmissionDecision admit(AdmissionRequest request) {
        if (request.requestId() == null || request.requestId().isBlank()) {
            return invalid(request, DenyReason.INVALID_REQUEST.getDescription());
        }

        Object lock = inflightLocks.computeIfAbsent(request.requestId(), k -> new Object());
        try {
            synchronized (lock) {
                // 持久化幂等：重复提交直接返回首次结论
                Optional<AdmissionDecision> existing =
                        store.readAudit(request.requestId(), AdmissionDecision.class)
                                .map(o -> (AdmissionDecision) o);
                if (existing.isPresent()) {
                    AdmissionDecision cached = existing.get();
                    log.info("幂等命中 requestId={} effect={}", request.requestId(), cached.effect());
                    return new AdmissionDecision(cached.requestId(), cached.effect(),
                            cached.denyReasons(), cached.artifactDigest(), cached.keyId(),
                            cached.keyState(), cached.policyVersion(), cached.matchedRule(),
                            cached.evaluatedAt(), true, cached.detail());
                }

                AdmissionDecision decision = evaluate(request);
                store.writeAuditIfAbsent(request.requestId(), decision);
                log.info("准入判定完成 requestId={} effect={} reasons={} rule={}",
                        request.requestId(), decision.effect(),
                        decision.denyReasons(), decision.matchedRule());
                return decision;
            }
        } finally {
            inflightLocks.remove(request.requestId());
        }
    }

    private AdmissionDecision evaluate(AdmissionRequest request) {
        long evaluationTime = request.evaluateAt() == null
                ? System.currentTimeMillis() : request.evaluateAt();
        List<String> denyReasons = new ArrayList<>();
        Map<String, String> detail = new LinkedHashMap<>();

        // 1) 制品规范化与摘要
        byte[] canonicalArtifact;
        Map<String, Object> artifactMap;
        String artifactDigest = null;
        try {
            canonicalArtifact = JsonCanonicalizer.canonicalize(request.artifact());
            artifactDigest = JsonCanonicalizer.sha256HexBytes(canonicalArtifact);
            artifactMap = mapper.readValue(canonicalArtifact, Map.class);
            detail.put("canonicalSize", String.valueOf(canonicalArtifact.length));
        } catch (Exception e) {
            denyReasons.add(DenyReason.MALFORMED_ARTIFACT.name());
            detail.put("error", e.getMessage());
            return deny(request, denyReasons, artifactDigest, null, null, null, null,
                    evaluationTime, detail);
        }

        // 2) 证明存在性与材料完整性
        if (request.attestation() == null || request.attestation().isBlank()) {
            denyReasons.add(DenyReason.MISSING_ATTESTATION.name());
            return deny(request, denyReasons, artifactDigest, null, null, null, null,
                    evaluationTime, detail);
        }
        Map<String, Object> attestation;
        try {
            attestation = mapper.readValue(
                    JsonCanonicalizer.canonicalize(request.attestation()), Map.class);
        } catch (Exception e) {
            denyReasons.add(DenyReason.MALFORMED_ATTESTATION.name());
            detail.put("error", e.getMessage());
            return deny(request, denyReasons, artifactDigest, null, null, null, null,
                    evaluationTime, detail);
        }
        String keyId = str(attestation.get("keyId"));
        String signature = str(attestation.get("signature"));
        String claimedDigest = str(attestation.get("artifactDigest"));
        Long issuedAt = longValue(attestation.get("issuedAt"));
        Long notBefore = longValue(attestation.get("notBefore"));
        Long notAfter = longValue(attestation.get("notAfter"));
        String issuer = str(attestation.get("issuer"));
        if (isBlank(keyId) || isBlank(signature) || isBlank(claimedDigest)
                || issuedAt == null || notBefore == null || notAfter == null || isBlank(issuer)) {
            denyReasons.add(DenyReason.INCOMPLETE_SIGNATURE_MATERIAL.name());
            detail.put("missing", describeMissing(keyId, signature, claimedDigest,
                    issuedAt, notBefore, notAfter, issuer));
            return deny(request, denyReasons, artifactDigest, keyId, null, null, null,
                    evaluationTime, detail);
        }

        // 3) 密钥存在性
        Optional<KeyMaterial> keyOpt = store.findKey(keyId);
        if (keyOpt.isEmpty()) {
            denyReasons.add(DenyReason.UNKNOWN_KEY.name());
            detail.put("keyId", keyId);
            return deny(request, denyReasons, artifactDigest, keyId, null, null, null,
                    evaluationTime, detail);
        }
        KeyMaterial key = keyOpt.get();

        // 4) 签名本身是否成立（针对证明中被覆盖字段）
        byte[] payload = signatures.signaturePayload(attestation);
        boolean signatureValid = signatures.verify(payload, signature,
                signatures.loadPublicKey(key.publicKey()));
        if (!signatureValid) {
            denyReasons.add(DenyReason.SIGNATURE_MISMATCH.name());
            detail.put("signedPayload", new String(payload, java.nio.charset.StandardCharsets.UTF_8));
        }

        // 5) 制品摘要是否与证明一致（内容篡改与签名错误区分开）
        boolean digestMatch = artifactDigest.equals(claimedDigest);
        if (!digestMatch) {
            denyReasons.add(DenyReason.CONTENT_TAMPERED.name());
            detail.put("expectedDigest", claimedDigest);
            detail.put("actualDigest", artifactDigest);
        }

        // 6) 签发时刻密钥状态：吊销生效后/未生效/已过期的密钥不得签发
        KeyState stateAtIssuance = KeyStateEvaluator.stateAt(key, issuedAt);
        detail.put("keyStateAtIssuance", stateAtIssuance.name());
        if (stateAtIssuance == KeyState.NOT_YET_VALID) {
            denyReasons.add(DenyReason.KEY_NOT_VALID_YET.name());
        } else if (stateAtIssuance == KeyState.REVOKED) {
            denyReasons.add(DenyReason.KEY_REVOKED.name());
            detail.put("revokedAt", String.valueOf(key.revokedAt()));
            detail.put("revokedReason", String.valueOf(key.revokedReason()));
        } else if (stateAtIssuance == KeyState.EXPIRED) {
            denyReasons.add(DenyReason.KEY_EXPIRED.name());
        }

        // 7) 判定时刻的证明有效期
        if (evaluationTime < notBefore) {
            denyReasons.add(DenyReason.ATTESTATION_NOT_YET_VALID.name());
        } else if (evaluationTime > notAfter) {
            denyReasons.add(DenyReason.ATTESTATION_EXPIRED.name());
        }

        // 8) 判定时刻密钥状态（仅用于展示；吊销采用前瞻语义，
        //    吊销生效前签发且证明仍在有效期内时不追溯失效）
        KeyState stateAtEvaluation = KeyStateEvaluator.stateAt(key, evaluationTime);
        detail.put("keyStateAtEvaluation", stateAtEvaluation.name());

        // 9) 策略评估（签名/密钥/有效期全部通过后进行）
        String policyVersion = null;
        String matchedRule = null;
        if (denyReasons.isEmpty()) {
            PolicyDocument policy = policyEngine.selectPolicy(evaluationTime);
            if (policy == null) {
                denyReasons.add(DenyReason.POLICY_NOT_FOUND.name());
            } else {
                PolicyEngine.PolicyInput policyInput = PolicyEngine.PolicyInput.of(
                        artifactMap, issuer, keyId, canonicalArtifact.length, true);
                PolicyEngine.PolicyResult result = policyEngine.evaluate(policy, policyInput);
                policyVersion = result.policyVersion();
                matchedRule = result.matchedRule();
                detail.put("policyExplanation", result.explanation());
                if (!result.allow()) {
                    denyReasons.add(DenyReason.POLICY_DENIED.name());
                }
            }
        }

        return build(request, denyReasons, artifactDigest, keyId,
                stateAtEvaluation.name(), policyVersion, matchedRule, evaluationTime, detail);
    }

    @SuppressWarnings("unchecked")
    public Optional<AdmissionDecision> findAudited(String requestId) {
        return store.readAudit(requestId, AdmissionDecision.class).map(o -> (AdmissionDecision) o);
    }

    private AdmissionDecision deny(AdmissionRequest request, List<String> denyReasons,
                                   String digest, String keyId, String keyState,
                                   String policyVersion, String matchedRule,
                                   long evaluationTime, Map<String, String> detail) {
        return build(request, denyReasons, digest, keyId, keyState,
                policyVersion, matchedRule, evaluationTime, detail);
    }

    private AdmissionDecision build(AdmissionRequest request, List<String> denyReasons,
                                    String digest, String keyId, String keyState,
                                    String policyVersion, String matchedRule,
                                    long evaluationTime, Map<String, String> detail) {
        for (String reason : denyReasons) {
            detail.putIfAbsent("reason." + reason,
                    DenyReason.valueOf(reason).getDescription());
        }
        return new AdmissionDecision(request.requestId(),
                denyReasons.isEmpty() ? "ALLOW" : "DENY",
                List.copyOf(denyReasons), digest, keyId, keyState,
                policyVersion, matchedRule, evaluationTime, false,
                Map.copyOf(detail));
    }

    private AdmissionDecision invalid(AdmissionRequest request, String message) {
        return new AdmissionDecision(
                request.requestId() == null ? "<unknown>" : request.requestId(),
                "DENY", List.of(DenyReason.INVALID_REQUEST.name()),
                null, null, null, null, null,
                request.evaluateAt() == null ? 0L : request.evaluateAt(),
                false, Map.of("error", message));
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private Long longValue(Object o) {
        return o instanceof Number n ? n.longValue() : null;
    }

    private String describeMissing(String keyId, String signature, String digest,
                                   Long issuedAt, Long notBefore, Long notAfter, String issuer) {
        List<String> missing = new ArrayList<>();
        if (isBlank(keyId)) missing.add("keyId");
        if (isBlank(signature)) missing.add("signature");
        if (isBlank(digest)) missing.add("artifactDigest");
        if (issuedAt == null) missing.add("issuedAt");
        if (notBefore == null) missing.add("notBefore");
        if (notAfter == null) missing.add("notAfter");
        if (isBlank(issuer)) missing.add("issuer");
        return String.join(",", missing);
    }
}

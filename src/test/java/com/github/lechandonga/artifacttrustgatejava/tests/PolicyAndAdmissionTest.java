package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.model.AdmissionRequest;
import com.github.lechandonga.artifacttrustgatejava.model.ArtifactRef;
import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionResult;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyRule;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.tests.support.BusinessLoggingExtension;
import com.github.lechandonga.artifacttrustgatejava.tests.support.LocalHarness;
import com.github.lechandonga.artifacttrustgatejava.tests.support.TestClock;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务覆盖：策略版本化与生效顺序、准入幂等、审计去重、并发不互相覆盖/串数据。
 */
@DisplayName("准入策略、版本复现、审计幂等与并发")
@ExtendWith(BusinessLoggingExtension.class)
class PolicyAndAdmissionTest {

    private static final String CONTENT = "{\"name\":\"svc\",\"version\":\"1.0\"}";
    private static final String CONTENT_V2 = "{\"name\":\"svc\",\"version\":\"2.0\"}";

    @TempDir
    Path tempDir;

    private TestClock clock;
    private LocalHarness harness;

    @BeforeEach
    void setUp() {
        clock = new TestClock(Instant.parse("2026-01-10T08:00:00Z"));
        harness = LocalHarness.create(tempDir, clock);
        harness.adminService().generateKey("key-a");
        harness.adminService().generateKey("key-b");
    }

    @Test
    @DisplayName("策略按声明顺序 first-match：具体规则优先于默认规则")
    void firstMatchOrder() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "A 放行"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation byA = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofHours(1));
        Attestation byB = harness.attestationService().issue(
                "key-b", Digests.artifactDigest(CONTENT_V2), Duration.ofHours(1));

        DecisionResult ra = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), byA, null, null, null));
        DecisionResult rb = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT_V2), byB, null, null, null));

        assertTrue(ra.allowed());
        assertEquals("allow-a", ra.matchedRuleId());
        assertFalse(rb.allowed());
        assertEquals("REJECT_POLICY_DENY", rb.code().name());
        assertEquals("default-deny", rb.matchedRuleId());
    }

    @Test
    @DisplayName("策略变更可追溯：同一制品在 v1 放行、v2 拒绝，分别复现并说明命中规则")
    void policyVersionReproduction() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "v1 放行"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("deny-a", "key-a", false, "v2 收紧：A 也拒绝"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));

        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(30));

        DecisionResult latestV2 = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation, null, null, null));
        DecisionResult pinnedV1 = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation, null, 1, null));
        DecisionResult pinnedV2 = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation, null, 2, null));

        assertFalse(latestV2.allowed());
        assertEquals(2, latestV2.policyVersion());
        assertEquals("deny-a", latestV2.matchedRuleId());
        assertTrue(pinnedV1.allowed());
        assertEquals(1, pinnedV1.policyVersion());
        assertEquals("allow-a", pinnedV1.matchedRuleId());
        assertFalse(pinnedV2.allowed());
        assertEquals("deny-a", pinnedV2.matchedRuleId());
    }

    @Test
    @DisplayName("策略版本不存在 → REJECT_POLICY_VERSION_UNKNOWN")
    void unknownPolicyVersion() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofHours(1));
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.admissionService().submit(new AdmissionRequest(
                        new ArtifactRef(CONTENT), attestation, null, 99, null)));
        assertEquals("REJECT_POLICY_VERSION_UNKNOWN", ex.code().name());
    }

    @Test
    @DisplayName("拒绝原因可区分：篡改/缺证明/缺签名/过期 分别返回不同 code")
    void distinctRejectionReasons() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofHours(1));

        DecisionResult tampered = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT_V2), attestation, null, null, null));
        assertEquals("REJECT_CONTENT_DIGEST_MISMATCH", tampered.code().name());

        DecisionResult noAtt = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), null, null, null, null));
        assertEquals("REJECT_ATTESTATION_MISSING", noAtt.code().name());

        Attestation unsigned = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), attestation.keyId(),
                attestation.issuedAt(), attestation.expiresAt(), null);
        DecisionResult noSig = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), unsigned, null, null, null));
        assertEquals("REJECT_SIGNATURE_MISSING", noSig.code().name());

        DecisionResult expired = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation,
                        attestation.expiresAt().plusSeconds(1), null, null));
        assertEquals("REJECT_ATTESTATION_EXPIRED", expired.code().name());
    }

    @Test
    @DisplayName("幂等：同一制品重复提交结论一致，第二次 reusedAuditRecord=true 且审计不新增；材料不同不串结论")
    void idempotentSubmissionDeduplicatesAudit() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "放行"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofHours(1));

        AdmissionRequest request = new AdmissionRequest(
                new ArtifactRef(CONTENT), attestation, null, null, null);
        DecisionResult first = harness.admissionService().submit(request);
        DecisionResult second = harness.admissionService().submit(request);
        DecisionResult third = harness.admissionService().submit(new AdmissionRequest(
                new ArtifactRef("{\n\"version\":\"1.0\", \"name\":\"svc\"\n}"),
                attestation, null, null, null));

        assertTrue(first.allowed());
        assertFalse(first.reusedAuditRecord());
        assertTrue(second.reusedAuditRecord());
        assertTrue(third.reusedAuditRecord());
        assertEquals(first.submissionId(), second.submissionId());
        assertEquals(first.submissionId(), third.submissionId());
        assertEquals(1, harness.auditStore().findAll().size());

        // 回归：缺签名的提交绝不能复用之前 ALLOW 的结论
        Attestation unsigned = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), attestation.keyId(),
                attestation.issuedAt(), attestation.expiresAt(), null);
        DecisionResult noSig = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), unsigned, null, null, null));
        assertEquals("REJECT_SIGNATURE_MISSING", noSig.code().name());
        assertFalse(noSig.reusedAuditRecord());
        assertEquals(2, harness.auditStore().findAll().size());
    }

    @Test
    @DisplayName("不同策略版本分别留审计；同键重复仍去重")
    void auditKeyedByContext() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "v1"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("deny-a", "key-a", false, "v2"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(30));

        harness.admissionService().submit(new AdmissionRequest(
                new ArtifactRef(CONTENT), attestation, null, 1, null));
        harness.admissionService().submit(new AdmissionRequest(
                new ArtifactRef(CONTENT), attestation, null, 1, null));
        harness.admissionService().submit(new AdmissionRequest(
                new ArtifactRef(CONTENT), attestation, null, 2, null));

        assertEquals(2, harness.auditStore().findAll().size());
    }

    @Test
    @DisplayName("并发：32 个相同提交只产生 1 条审计，所有响应结论一致")
    void concurrentSameSubmissionSingleAudit() throws Exception {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "放行"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofHours(1));

        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Callable<DecisionResult>> tasks = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> harness.admissionService().submit(new AdmissionRequest(
                    new ArtifactRef(CONTENT), attestation, null, null, null)));
        }
        List<Future<DecisionResult>> futures = pool.invokeAll(tasks);
        pool.shutdown();

        long allowed = futures.stream().filter(f -> {
            try {
                return f.get().allowed();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).count();
        long reused = futures.stream().filter(f -> {
            try {
                return f.get().reusedAuditRecord();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).count();

        assertEquals(threads, allowed);
        assertEquals(threads - 1, reused);
        assertEquals(1, harness.auditStore().findAll().size());
    }

    @Test
    @DisplayName("并发：不同制品互不覆盖、不串数据，各自独立审计")
    void concurrentDistinctArtifactsDoNotBleed() throws Exception {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "放行"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));

        int variants = 20;
        List<AdmissionRequest> requests = new java.util.ArrayList<>();
        for (int i = 0; i < variants; i++) {
            String content = "{\"name\":\"svc\",\"build\":" + i + "}";
            Attestation attestation = harness.attestationService().issue(
                    "key-a", Digests.artifactDigest(content), Duration.ofHours(1));
            requests.add(new AdmissionRequest(
                    new ArtifactRef(content), attestation, null, null, null));
        }

        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Callable<DecisionResult>> tasks = new java.util.ArrayList<>();
        for (AdmissionRequest request : requests) {
            tasks.add(() -> harness.admissionService().submit(request));
        }
        List<Future<DecisionResult>> futures = pool.invokeAll(tasks);
        pool.shutdown();

        java.util.Set<String> digests = new java.util.HashSet<>();
        for (Future<DecisionResult> f : futures) {
            DecisionResult result = f.get();
            assertTrue(result.allowed(), "每个制品都应独立判定为放行");
            digests.add(result.artifactDigest());
        }
        assertEquals(variants, digests.size(), "20 个不同制品必须有 20 个不同指纹，无串数据");
        assertEquals(variants, harness.auditStore().findAll().size());
    }

    @Test
    @DisplayName("指定历史评估时间可复现：证明过期前后的结论分别可回放")
    void evaluationTimeReproduction() {
        harness.adminService().publishPolicy(List.of(
                new PolicyRule("allow-a", "key-a", true, "放行"),
                new PolicyRule("default-deny", null, false, "默认拒绝")));
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofHours(1));

        Instant within = attestation.issuedAt().plusSeconds(60);
        Instant expiredAt = attestation.expiresAt().plusSeconds(60);
        DecisionResult whenValid = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation, within, null, null));
        DecisionResult whenExpired = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation, expiredAt, null, null));

        assertTrue(whenValid.allowed());
        assertEquals("REJECT_ATTESTATION_EXPIRED", whenExpired.code().name());

        // 再用旧时间重放，仍能拿回当时结论（审计中按评估上下文区分两条）
        DecisionResult replay = harness.admissionService().submit(
                new AdmissionRequest(new ArtifactRef(CONTENT), attestation, within, null, null));
        assertEquals(whenValid.submissionId(), replay.submissionId());
        assertTrue(replay.reusedAuditRecord());
    }
}

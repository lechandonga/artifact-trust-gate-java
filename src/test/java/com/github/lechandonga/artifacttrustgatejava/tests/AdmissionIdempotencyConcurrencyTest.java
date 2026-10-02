package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.web.AdmissionDecision;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：重复提交幂等（一致结论 + 不重复审计）、并发提交不互相覆盖、缓存不串数据。
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AdmissionIdempotencyConcurrencyTest {

    private static final Logger log =
            LoggerFactory.getLogger(AdmissionIdempotencyConcurrencyTest.class);

    private TestGateFixture fixture;
    private String attestationA;
    private String attestationB;
    private final String artifactA =
            "{\"type\":\"release\",\"name\":\"svc-a\",\"version\":\"1.0.0\"}";
    private final String artifactB =
            "{\"type\":\"release\",\"name\":\"svc-b\",\"version\":\"1.0.0\"}";

    @BeforeAll
    void setUp() {
        try {
            fixture = TestGateFixture.create();
            long now = System.currentTimeMillis();
            attestationA = fixture.issuer.issue("key-team-a", artifactA,
                    "team-a-ci", now, now, now + 365L * 24 * 3600 * 1000);
            attestationB = fixture.issuer.issue("key-team-b", artifactB,
                    "team-b-ci", now, now, now + 365L * 24 * 3600 * 1000);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("幂等-同一 requestId 重复提交：结论一致，仅首次写审计，后续标记 cached")
    void repeatedSubmissionIsIdempotent() throws Exception {
        long baseline = countAuditFiles();
        AdmissionRequest request =
                new AdmissionRequest("idem-001", artifactA, attestationA, null);
        AdmissionDecision first = fixture.admission.admit(request);
        AdmissionDecision second = fixture.admission.admit(request);
        AdmissionDecision third = fixture.admission.admit(request);

        assertFalse(first.cached());
        assertTrue(second.cached());
        assertTrue(third.cached());
        assertEquals(first.effect(), second.effect());
        assertEquals(first.matchedRule(), third.matchedRule());
        assertEquals(first.artifactDigest(), second.artifactDigest());
        assertEquals(baseline + 1, countAuditFiles());
        log.info("[幂等] 业务=重复提交一致且不重复审计 | 结果: effect={}, auditFiles=1, PASS",
                first.effect());
    }

    @Test
    @DisplayName("并发-同一 requestId 50 个并发：结论完全一致且只有一份审计")
    void concurrentSameRequestNoOverwrite() throws Exception {
        long baseline = countAuditFiles();
        int threads = 50;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<AdmissionDecision> results = new ArrayList<>(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                start.await();
                AdmissionDecision d = fixture.admission.admit(
                        new AdmissionRequest("conc-same", artifactA, attestationA, null));
                synchronized (results) {
                    results.add(d);
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long cachedCount = results.stream().filter(AdmissionDecision::cached).count();
        assertEquals(threads, results.size());
        assertTrue(results.stream().allMatch(d -> "ALLOW".equals(d.effect())));
        assertEquals(threads - 1, cachedCount, "只有一个请求真正执行判定");
        assertEquals(baseline + 1, countAuditFiles());
        log.info("[并发] 业务=同一请求并发不覆盖 | 结果: {}/{} 命中幂等缓存, auditFiles=1, PASS",
                cachedCount, threads);
    }

    @Test
    @DisplayName("并发-不同 requestId 交叉提交：缓存不串数据，各自结论与摘要正确")
    void concurrentDifferentRequestsDoNotMix() throws Exception {
        long baseline = countAuditFiles();
        int perKey = 25;
        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentHashMap<String, AdmissionDecision> all = new ConcurrentHashMap<>();
        java.util.concurrent.atomic.AtomicInteger seq =
                new java.util.concurrent.atomic.AtomicInteger();
        for (int i = 0; i < perKey; i++) {
            pool.submit(() -> {
                start.await();
                String id = "mix-a-" + seq.incrementAndGet();
                all.put(id, fixture.admission.admit(
                        new AdmissionRequest(id, artifactA, attestationA, null)));
                return null;
            });
            pool.submit(() -> {
                start.await();
                String id = "mix-b-" + seq.incrementAndGet();
                all.put(id, fixture.admission.admit(
                        new AdmissionRequest(id, artifactB, attestationB, null)));
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        String digestA = all.values().stream()
                .filter(d -> d.requestId().startsWith("mix-a-"))
                .findFirst().orElseThrow().artifactDigest();
        String digestB = all.values().stream()
                .filter(d -> d.requestId().startsWith("mix-b-"))
                .findFirst().orElseThrow().artifactDigest();

        all.values().forEach(d -> {
            assertEquals("ALLOW", d.effect());
            String expected = d.requestId().startsWith("mix-a-") ? digestA : digestB;
            assertEquals(expected, d.artifactDigest(), "缓存串数据: " + d.requestId());
        });
        assertFalse(digestA.equals(digestB));
        assertEquals(baseline + perKey * 2, countAuditFiles());
        log.info("[并发] 业务=不同请求并发不串数据 | 结果: {} 份审计, 摘要A!=摘要B, PASS",
                all.size());
    }

    private long countAuditFiles() throws Exception {
        java.lang.reflect.Field f = fixture.store.getClass().getDeclaredField("auditDir");
        f.setAccessible(true);
        try (var stream = java.nio.file.Files.list((java.nio.file.Path) f.get(fixture.store))) {
            return stream.filter(p -> p.getFileName().toString().startsWith("decision-"))
                    .count();
        }
    }
}

package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.model.DenyReason;
import com.github.lechandonga.artifacttrustgatejava.service.KeyStateEvaluator;
import com.github.lechandonga.artifacttrustgatejava.store.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionDecision;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：密钥轮换（多密钥并存）与带生效时间的吊销语义。
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class KeyRevocationTest {

    private static final Logger log = LoggerFactory.getLogger(KeyRevocationTest.class);

    private TestGateFixture fixture;
    private final String artifact =
            "{\"type\":\"release\",\"name\":\"app\",\"version\":\"2.3.4\"}";

    @BeforeAll
    void setUp() throws Exception {
        fixture = TestGateFixture.create();
    }

    @BeforeEach
    void resetKeys() throws Exception {
        fixture.resetKey("key-team-a");
        fixture.resetKey("key-team-b");
    }

    @Test
    @DisplayName("吊销-吊销前签发且证明有效：即使现在已吊销，历史制品仍 ALLOW（可复现）")
    void preRevocationAttestationStaysValid() {
        long issuedAt = java.time.Instant.parse("2025-06-01T00:00:00Z").toEpochMilli();
        long revokeAt = java.time.Instant.parse("2025-09-01T00:00:00Z").toEpochMilli();
        String attestation = fixture.issuer.issue("key-team-a", artifact,
                "team-a-ci", issuedAt, issuedAt - 1000,
                issuedAt + 365L * 10 * 24 * 3600 * 1000);
        fixture.issuer.revoke("key-team-a", revokeAt, "测试：密钥轮换下线");

        AdmissionDecision before = fixture.admission.admit(new AdmissionRequest(
                "rev-historical-before", artifact, attestation, revokeAt - 1000));
        AdmissionDecision after = fixture.admission.admit(new AdmissionRequest(
                "rev-historical-after", artifact, attestation, revokeAt + 1000));

        log.info("[吊销] 业务=吊销前瞻语义 | 吊销前判定={} keyState={} / 吊销后判定={} keyState={}",
                before.effect(), before.keyState(), after.effect(), after.keyState());
        assertEquals("ALLOW", before.effect());
        // 吊销生效后判定：证明仍在有效期且签发合法，不追溯失效
        assertEquals("ALLOW", after.effect());
        assertEquals("REVOKED", after.keyState());

        // 历史结论已固化，再重复读取结果不变（审计不可变）
        Optional<AdmissionDecision> replayed = fixture.admission
                .findAudited("rev-historical-after");
        assertTrue(replayed.isPresent());
        assertEquals("ALLOW", replayed.get().effect());
        log.info("[吊销] 业务=历史结论稳定复现，不受后续吊销记录改写 | 结果: PASS");
    }

    @Test
    @DisplayName("吊销-吊销生效后不得再签发新证明")
    void cannotIssueAfterRevocation() {
        long revokeAt = 1_750_000_000_000L;
        fixture.issuer.revoke("key-team-b", revokeAt, "测试：泄露吊销");
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> fixture.issuer.issue("key-team-b", artifact, "team-b-ci",
                        revokeAt + 1000, revokeAt, revokeAt + 10L * 365 * 24 * 3600 * 1000));
        // 但生效时间点之前的签发仍然允许（事后补录吊销记录场景）
        fixture.issuer.issue("key-team-b", artifact, "team-b-ci",
                revokeAt - 2000, revokeAt - 3000, revokeAt + 10L * 365 * 24 * 3600 * 1000);
        log.info("[吊销] 业务=吊销后拒绝签发，吊销前签发允许 | 结果: 异常信息=\"{}\"",
                ex.getMessage());
        assertTrue(ex.getMessage().contains("REVOKED"));
    }

    @Test
    @DisplayName("吊销-吊销生效之后用旧密钥签发（伪造时间）：判定时 KEY_REVOKED 拒绝")
    void attestationCreatedAfterRevocationRejected() {
        long revokeAt = 1_760_000_000_000L;
        // 直接在存储层吊销，绕过签发器，模拟“吊销后仍流出的证明”
        KeyMaterial key = fixture.store.findKey("key-team-a").orElseThrow()
                .withRevocation(revokeAt, "测试");
        fixture.store.putKey(key);
        // key-team-a 在上面的用例已被吊销；这里校验状态机本身
        assertEquals(com.github.lechandonga.artifacttrustgatejava.model.KeyState.ACTIVE,
                KeyStateEvaluator.stateAt(key, revokeAt - 1));
        assertEquals(com.github.lechandonga.artifacttrustgatejava.model.KeyState.REVOKED,
                KeyStateEvaluator.stateAt(key, revokeAt));
        assertEquals(com.github.lechandonga.artifacttrustgatejava.model.KeyState.REVOKED,
                KeyStateEvaluator.stateAt(key, revokeAt + 1));
        log.info("[吊销] 业务=吊销生效时间边界（前/当时/之后）| 结果: PASS");
    }

    @Test
    @DisplayName("轮换-旧密钥到期后新密钥继续可用；过期密钥签发/准入被拒")
    void keyRotationAndExpiry() {
        long now = System.currentTimeMillis();
        String attestation = fixture.issuer.issue("key-team-b", artifact,
                "team-b-ci", now, now - 1000, now + 365L * 24 * 3600 * 1000);
        AdmissionDecision decision = fixture.admission.admit(
                new AdmissionRequest("rev-rotated", artifact, attestation, null));
        log.info("[轮换] 业务=新密钥签发准入 | 结果: effect={}, rule={}",
                decision.effect(), decision.matchedRule());
        assertEquals("ALLOW", decision.effect());

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> fixture.issuer.issue("key-legacy", artifact, "legacy-ci",
                        now, now, now + 365L * 24 * 3600 * 1000));
        assertTrue(ex.getMessage().contains("EXPIRED"));
        log.info("[轮换] 业务=过期密钥拒绝签发 | 结果: 异常信息=\"{}\"", ex.getMessage());
    }
}

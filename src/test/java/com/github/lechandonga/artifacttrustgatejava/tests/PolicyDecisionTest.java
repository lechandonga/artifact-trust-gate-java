package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.model.DenyReason;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionDecision;
import com.github.lechandonga.artifacttrustgatejava.web.AdmissionRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：版本化准入策略——历史时间点复现、规则命中说明、规则顺序、默认拒绝。
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PolicyDecisionTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyDecisionTest.class);

    private TestGateFixture fixture;
    private final String releaseArtifact =
            "{\"type\":\"release\",\"name\":\"app\",\"version\":\"9.9.9\"}";

    @BeforeAll
    void setUp() throws Exception {
        fixture = TestGateFixture.create();
    }

    private AdmissionDecision admit(String requestId, String keyId, String issuer,
                                    String artifact, Long evaluateAt) {
        long issuedAt = (evaluateAt == null ? System.currentTimeMillis() : evaluateAt);
        String attestation = fixture.issuer.issue(keyId, artifact, issuer,
                issuedAt, issuedAt - 365L * 24 * 3600 * 1000,
                issuedAt + 365L * 10 * 24 * 3600 * 1000);
        return fixture.admission.admit(
                new AdmissionRequest(requestId, artifact, attestation, evaluateAt));
    }

    @Test
    @DisplayName("策略-同一制品在 v1/v2 下分别复现：v1 拒绝 team-b，v2 放行并命中新规则")
    void sameArtifactDifferentPolicyVersions() {
        long v1Time = Instant.parse("2025-06-01T00:00:00Z").toEpochMilli();
        long v2Time = Instant.parse("2026-06-01T00:00:00Z").toEpochMilli();

        AdmissionDecision underV1 = admit("pol-team-b-v1", "key-team-b",
                "team-b-ci", releaseArtifact, v1Time);
        AdmissionDecision underV2 = admit("pol-team-b-v2", "key-team-b",
                "team-b-ci", releaseArtifact, v2Time);

        log.info("[策略] 业务=策略版本选择 | v1: effect={}, rule={} / v2: effect={}, rule={}",
                underV1.effect(), underV1.matchedRule(), underV2.effect(), underV2.matchedRule());
        assertEquals("1", underV1.policyVersion());
        assertEquals("DENY", underV1.effect());
        assertTrue(underV1.denyReasons().contains(DenyReason.POLICY_DENIED.name()));
        assertEquals("2", underV2.policyVersion());
        assertEquals("ALLOW", underV2.effect());
        assertEquals("allow-team-b-release", underV2.matchedRule());
    }

    @Test
    @DisplayName("策略-规则按顺序首条命中：不受信任签发者先于放行规则被拒")
    void ruleOrderFirstMatchWins() {
        AdmissionDecision decision = admit("pol-untrusted", "key-team-a",
                "untrusted", releaseArtifact, null);
        log.info("[策略] 业务=规则顺序 | 结果: effect={}, rule={}",
                decision.effect(), decision.matchedRule());
        assertEquals("DENY", decision.effect());
        assertEquals("reject-untrusted-issuer", decision.matchedRule());
    }

    @Test
    @DisplayName("策略-无规则命中走默认拒绝")
    void defaultDenyWhenNoRuleMatches() {
        String snapshot = "{\"type\":\"snapshot\",\"name\":\"app\",\"version\":\"dev\"}";
        AdmissionDecision decision = admit("pol-snapshot", "key-team-a",
                "team-a-ci", snapshot, null);
        log.info("[策略] 业务=默认拒绝 | 结果: effect={}, rule={}, explain={}",
                decision.effect(), decision.matchedRule(),
                decision.detail().get("policyExplanation"));
        assertEquals("DENY", decision.effect());
        assertTrue(decision.matchedRule().startsWith("<default:"));
    }

    @Test
    @DisplayName("策略-超尺寸约束拒绝")
    void maxArtifactSizeConstraint() {
        String big = "{\"type\":\"release\",\"name\":\"app\",\"version\":\"1\",\"data\":\""
                + "x".repeat(5000) + "\"}";
        AdmissionDecision decision = admit("pol-too-big", "key-team-a",
                "team-a-ci", big, null);
        log.info("[策略] 业务=制品大小上限 | 结果: effect={}, canonicalSize={}",
                decision.effect(), decision.detail().get("canonicalSize"));
        assertEquals("DENY", decision.effect());
        assertTrue(decision.matchedRule().startsWith("<default:"));
    }
}

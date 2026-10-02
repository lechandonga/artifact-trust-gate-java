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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务：签名与证明校验主流程及边界。
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SignatureVerificationTest {

    private static final Logger log = LoggerFactory.getLogger(SignatureVerificationTest.class);

    private TestGateFixture fixture;
    private final String artifact =
            "{\"type\":\"release\",\"name\":\"app\",\"version\":\"1.0.0\"}";

    @BeforeAll
    void setUp() throws Exception {
        fixture = TestGateFixture.create();
    }

    @Test
    @DisplayName("签名-合法证明且字段顺序变化：ALLOW，结论一致")
    void validSignatureWithReorderedArtifact() {
        long now = System.currentTimeMillis();
        String attestation = fixture.issuer.issue("key-team-a", artifact,
                "team-a-ci", now, now, now + 365L * 24 * 3600 * 1000);
        String reorderedArtifact =
                "{\n \"version\":\"1.0.0\",\n \"name\":\"app\",\n \"type\":\"release\"\n}";

        AdmissionDecision d1 = fixture.admission.admit(
                new AdmissionRequest("sig-ok-1", reorderedArtifact, attestation, null));
        AdmissionDecision d2 = fixture.admission.admit(
                new AdmissionRequest("sig-ok-2", " " + artifact + " ", attestation, null));

        log.info("[签名] 业务=字段顺序/空白差异仍 ALLOW | 结果: effect={}, digest={}",
                d1.effect(), d1.artifactDigest());
        assertEquals("ALLOW", d1.effect());
        assertEquals("ALLOW", d2.effect());
        assertEquals(d1.artifactDigest(), d2.artifactDigest());
    }

    @Test
 @DisplayName("签名-制品内容被篡改：CONTENT_TAMPERED（区别于签名错误）")
    void tamperedArtifact() {
        long now = System.currentTimeMillis();
        String attestation = fixture.issuer.issue("key-team-a", artifact,
                "team-a-ci", now, now, now + 365L * 24 * 3600 * 1000);
        String tampered = artifact.replace("1.0.0", "1.0.1");

        AdmissionDecision decision = fixture.admission.admit(
                new AdmissionRequest("sig-tampered", tampered, attestation, null));
        log.info("[签名] 业务=内容篡改拒绝 | 结果: effect={}, reasons={}",
                decision.effect(), decision.denyReasons());
        assertEquals("DENY", decision.effect());
        assertTrue(decision.denyReasons().contains(DenyReason.CONTENT_TAMPERED.name()));
        assertFalse(decision.denyReasons().contains(DenyReason.SIGNATURE_MISMATCH.name()));
    }

    @Test
    @DisplayName("签名-签名值被改：SIGNATURE_MISMATCH（区别于内容篡改）")
    void corruptedSignature() {
        long now = System.currentTimeMillis();
        String attestation = fixture.issuer.issue("key-team-a", artifact,
                "team-a-ci", now, now, now + 365L * 24 * 3600 * 1000);
        String corrupted = attestation.replaceFirst("\"signature\":\"[A-Za-z0-9+/=]+",
                "\"signature\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        AdmissionDecision decision = fixture.admission.admit(
                new AdmissionRequest("sig-corrupt", artifact, corrupted, null));
        log.info("[签名] 业务=签名不匹配拒绝 | 结果: effect={}, reasons={}",
                decision.effect(), decision.denyReasons());
        assertEquals("DENY", decision.effect());
        assertTrue(decision.denyReasons().contains(DenyReason.SIGNATURE_MISMATCH.name()));
        assertFalse(decision.denyReasons().contains(DenyReason.CONTENT_TAMPERED.name()));
    }

    @Test
    @DisplayName("签名-缺失证明 / 材料不完整 / 未知密钥：三种原因分开拒绝")
    void missingAndIncompleteMaterials() {
        AdmissionDecision missing = fixture.admission.admit(
                new AdmissionRequest("sig-missing", artifact, null, null));
        AdmissionDecision incomplete = fixture.admission.admit(
                new AdmissionRequest("sig-incomplete", artifact,
                        "{\"keyId\":\"key-team-a\"}", null));
        AdmissionDecision unknownKey = fixture.admission.admit(
                new AdmissionRequest("sig-unknown", artifact,
                        attestationForUnknownKey(artifact), null));

        log.info("[签名] 业务=缺失证明/材料不完整/未知密钥分开拒绝 | 结果: {}, {}, {}",
                missing.denyReasons(), incomplete.denyReasons(), unknownKey.denyReasons());
        assertTrue(missing.denyReasons().contains(DenyReason.MISSING_ATTESTATION.name()));
        assertTrue(incomplete.denyReasons()
                .contains(DenyReason.INCOMPLETE_SIGNATURE_MATERIAL.name()));
        assertTrue(unknownKey.denyReasons().contains(DenyReason.UNKNOWN_KEY.name()));
    }

    private String attestationForUnknownKey(String content) {
        long now = System.currentTimeMillis();
        return fixture.issuer.issue("key-team-a", content, "team-a-ci",
                now, now, now + 365L * 24 * 3600 * 1000)
                .replace("key-team-a", "key-ghost");
    }
}

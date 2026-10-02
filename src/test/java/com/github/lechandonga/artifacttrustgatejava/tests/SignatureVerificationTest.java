package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.crypto.RsaSignatureService;
import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.model.ArtifactRef;
import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.tests.support.BusinessLoggingExtension;
import com.github.lechandonga.artifacttrustgatejava.tests.support.LocalHarness;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 业务覆盖：签名校验主流程与边界——
 * 合法证明通过；内容篡改、证明被改、错密钥签名、缺签名、未知密钥分别给出不同拒绝原因。
 */
@DisplayName("签名与证明校验")
@ExtendWith(BusinessLoggingExtension.class)
class SignatureVerificationTest {

    private static final String CONTENT_COMPACT = "{\"name\":\"svc\",\"version\":\"1.0\"}";
    private static final String CONTENT_PRETTY = "{\n  \"name\": \"svc\",\n  \"version\": \"1.0\"\n}";

    @TempDir
    Path tempDir;

    private LocalHarness harness;
    private Attestation attestation;
    private KeyBookSnapshot emptySnapshot;
    private Instant evaluationTime;

    @BeforeEach
    void setUp() {
        harness = LocalHarness.create(tempDir);
        harness.adminService().generateKey("key-a");
        attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT_COMPACT), Duration.ofHours(1));
        emptySnapshot = new KeyBookSnapshot(0, null, List.of());
        evaluationTime = harness.clock().instant().plusSeconds(60);
    }

    @Test
    @DisplayName("合法签名 + 字段顺序/空白差异 → 校验通过，结论一致")
    void validSignatureAcrossEquivalentContent() {
        var r1 = harness.verificationService().verify(
                new ArtifactRef(CONTENT_COMPACT), attestation, emptySnapshot, evaluationTime);
        var r2 = harness.verificationService().verify(
                new ArtifactRef(CONTENT_PRETTY), attestation, emptySnapshot, evaluationTime);
        assertEquals(r1.artifactDigest(), r2.artifactDigest());
        assertEquals("key-a", r1.key().keyId());
    }

    @Test
    @DisplayName("内容被篡改（指纹不符）→ REJECT_CONTENT_DIGEST_MISMATCH")
    void tamperedContent() {
        String tampered = "{\"name\":\"svc\",\"version\":\"9.9\"}";
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(tampered), attestation, emptySnapshot, evaluationTime));
        assertEquals("REJECT_CONTENT_DIGEST_MISMATCH", ex.code().name());
    }

    @Test
    @DisplayName("证明载荷被改后未重签 → REJECT_SIGNATURE_INVALID")
    void tamperedAttestationPayload() {
        Attestation altered = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), attestation.keyId(),
                attestation.issuedAt(),
                attestation.issuedAt().plus(Duration.ofDays(10)), // 延长有效期但签名没重算
                attestation.signature());
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), altered, emptySnapshot, evaluationTime));
        assertEquals("REJECT_SIGNATURE_INVALID", ex.code().name());
    }

    @Test
    @DisplayName("用另一把密钥的签名顶替 → REJECT_SIGNATURE_INVALID")
    void wrongKeySignature() {
        harness.adminService().generateKey("key-other");
        Attestation forged = harness.attestationService().issue(
                "key-other", Digests.artifactDigest(CONTENT_COMPACT), Duration.ofHours(1));
        Attestation withOtherKey = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), "key-a", attestation.issuedAt(),
                attestation.expiresAt(), forged.signature());
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), withOtherKey,
                        emptySnapshot, evaluationTime));
        assertEquals("REJECT_SIGNATURE_INVALID", ex.code().name());
    }

    @Test
    @DisplayName("签名本身是乱码 → REJECT_SIGNATURE_INVALID，而不是崩溃")
    void garbageSignature() {
        Attestation bad = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), attestation.keyId(),
                attestation.issuedAt(), attestation.expiresAt(), "%%%not-base64%%%");
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), bad, emptySnapshot, evaluationTime));
        assertEquals("REJECT_SIGNATURE_INVALID", ex.code().name());
    }

    @Test
    @DisplayName("缺少 signature → REJECT_SIGNATURE_MISSING（材料不完整，区别于签名错）")
    void missingSignature() {
        Attestation unsigned = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), attestation.keyId(),
                attestation.issuedAt(), attestation.expiresAt(), null);
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), unsigned, emptySnapshot, evaluationTime));
        assertEquals("REJECT_SIGNATURE_MISSING", ex.code().name());
    }

    @Test
    @DisplayName("完全没有证明 → REJECT_ATTESTATION_MISSING")
    void missingAttestation() {
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), null, emptySnapshot, evaluationTime));
        assertEquals("REJECT_ATTESTATION_MISSING", ex.code().name());
    }

    @Test
    @DisplayName("签名密钥未登记 → REJECT_KEY_UNKNOWN")
    void unknownKey() {
        Attestation byGhost = new Attestation(attestation.attestationId(),
                attestation.subjectDigest(), "key-ghost",
                attestation.issuedAt(), attestation.expiresAt(), attestation.signature());
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), byGhost, emptySnapshot, evaluationTime));
        assertEquals("REJECT_KEY_UNKNOWN", ex.code().name());
    }

    @Test
    @DisplayName("证明过期 → REJECT_ATTESTATION_EXPIRED")
    void expiredAttestation() {
        Instant afterExpiry = attestation.expiresAt().plusSeconds(1);
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), attestation,
                        emptySnapshot, afterExpiry));
        assertEquals("REJECT_ATTESTATION_EXPIRED", ex.code().name());
    }

    @Test
    @DisplayName("边界：评估时间恰为过期时刻 → 拒绝；早一秒 → 通过")
    void expiryBoundary() {
        assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT_COMPACT), attestation,
                        emptySnapshot, attestation.expiresAt()));
        var ok = harness.verificationService().verify(
                new ArtifactRef(CONTENT_COMPACT), attestation,
                emptySnapshot, attestation.expiresAt().minusSeconds(1));
        assertEquals("key-a", ok.key().keyId());
    }

    @Test
    @DisplayName("RSA 直接验签：签名可被验真，改一个明文字节即验不过")
    void rawRsaRoundTrip() {
        RsaSignatureService rsa = new RsaSignatureService();
        KeyPair pair = rsa.generateKeyPair();
        byte[] data = "trust-gate".getBytes(StandardCharsets.UTF_8);
        String sig = rsa.sign(data, pair.getPrivate());
        assertTrue(rsa.verify(data, sig, pair.getPublic()));
        byte[] tweaked = "trust-gatf".getBytes(StandardCharsets.UTF_8);
        assertFalse(rsa.verify(tweaked, sig, pair.getPublic()));
        byte[] decoded = Base64.getDecoder().decode(sig);
        assertTrue(decoded.length > 100);
    }
}

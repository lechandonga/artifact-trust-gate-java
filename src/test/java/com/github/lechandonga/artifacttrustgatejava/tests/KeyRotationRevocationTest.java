package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.model.ArtifactRef;
import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 业务覆盖：密钥轮换与吊销——
 * 吊销带生效时间；生效前签发且仍有效证明不受影响；生效后禁止新签发；
 * 历史判定按快照版本稳定复现，不被后来追加的吊销记录改写；拒绝倒填。
 */
@DisplayName("密钥轮换与吊销")
@ExtendWith(BusinessLoggingExtension.class)
class KeyRotationRevocationTest {

    private static final String CONTENT = "{\"name\":\"svc\",\"version\":\"1.0\"}";

    @TempDir
    Path tempDir;

    private TestClock clock;
    private LocalHarness harness;

    @BeforeEach
    void setUp() {
        clock = new TestClock(Instant.parse("2026-01-10T08:00:00Z"));
        harness = LocalHarness.create(tempDir, clock);
        harness.adminService().generateKey("key-a");
    }

    @Test
    @DisplayName("轮换：新密钥可签发，旧密钥材料保留可验证历史制品")
    void rotationKeepsOldKeyForVerification() {
        Attestation oldAttestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(30));

        clock.advanceSeconds(3600);
        harness.adminService().rotate("key-a", "key-a2");

        Attestation newAttestation = harness.attestationService().issue(
                "key-a2", Digests.artifactDigest(CONTENT), Duration.ofDays(30));
        assertEquals("key-a2", newAttestation.keyId());

        KeyBookSnapshot snapshot = harness.revocationLedger().latestSnapshot(clock.instant());
        var verifiedOld = harness.verificationService().verify(
                new ArtifactRef(CONTENT), oldAttestation, snapshot, clock.instant());
        assertEquals("key-a", verifiedOld.key().keyId());
        assertEquals("key-a2", harness.keyStore().find("key-a").orElseThrow().replacedBy());
    }

    @Test
    @DisplayName("定时吊销未生效前：旧证明有效，且仍可签发新证明")
    void futureRevocationNotYetEffective() {
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(30));
        Instant futureEffective = clock.instant().plus(Duration.ofDays(7));
        harness.adminService().revoke("key-a", futureEffective, "scheduled rotation");

        KeyBookSnapshot snapshot = harness.revocationLedger().latestSnapshot(clock.instant());
        var verified = harness.verificationService().verify(
                new ArtifactRef(CONTENT), attestation, snapshot, clock.instant());
        assertEquals("key-a", verified.key().keyId());

        Attestation newlyIssued = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(1));
        assertEquals("key-a", newlyIssued.keyId());
    }

    @Test
    @DisplayName("吊销生效后：不能再签发；生效后用该密钥的证明判 REJECT_KEY_REVOKED")
    void revocationBlocksIssuanceAndPostRevokedAttestations() {
        Instant effective = clock.instant().plus(Duration.ofHours(1));
        harness.adminService().revoke("key-a", effective, "leaked key");

        harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(30));

        clock.setInstant(effective.plusSeconds(1));
        ServiceException issueEx = assertThrows(ServiceException.class, () ->
                harness.attestationService().issue(
                        "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(1)));
        assertEquals("REJECT_KEY_REVOKED", issueEx.code().name());

        // 模拟留存私钥在吊销生效后被越权使用：签名本身合法，应由吊销语义拒绝
        Attestation after = harness.attestationService().issueAtBypass(
                "key-a", Digests.artifactDigest(CONTENT),
                effective.plusSeconds(5), Duration.ofDays(1));
        clock.setInstant(effective.plusSeconds(10));
        KeyBookSnapshot snapshot = harness.revocationLedger().latestSnapshot(clock.instant());
        ServiceException verifyEx = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT), after, snapshot, clock.instant()));
        assertEquals("REJECT_KEY_REVOKED", verifyEx.code().name());
    }

    @Test
    @DisplayName("关键语义：生效前签发且仍在有效期内的证明，吊销生效后依旧有效")
    void attestationBeforeRevocationSurvives() {
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(30));
        Instant effective = clock.instant().plus(Duration.ofHours(1));
        harness.adminService().revoke("key-a", effective, "rotation");

        clock.setInstant(effective.plus(Duration.ofDays(2)));
        KeyBookSnapshot snapshot = harness.revocationLedger().latestSnapshot(clock.instant());
        var verified = harness.verificationService().verify(
                new ArtifactRef(CONTENT), attestation, snapshot, clock.instant());
        assertEquals("key-a", verified.key().keyId());
    }

    @Test
    @DisplayName("历史复现：旧快照不受后来新增吊销影响；同一证明在新旧快照结论可不同")
    void historicalSnapshotsAreStable() {
        Attestation attestation = harness.attestationService().issue(
                "key-a", Digests.artifactDigest(CONTENT), Duration.ofDays(60));

        KeyBookSnapshot v0 = harness.revocationLedger().snapshotAt(0);
        assertEquals(0, v0.version());

        Instant effective = clock.instant().plus(Duration.ofHours(1));
        harness.adminService().revoke("key-a", effective, "later decision");
        KeyBookSnapshot v1 = harness.revocationLedger().latestSnapshot(clock.instant());
        assertEquals(1, v1.version());

        Instant after = effective.plusSeconds(10);
        var byOldSnapshot = harness.verificationService().verify(
                new ArtifactRef(CONTENT), attestation, v0, after);
        assertEquals("key-a", byOldSnapshot.key().keyId());

        Attestation postRevoked = harness.attestationService().issueAtBypass(
                "key-a", attestation.subjectDigest(),
                effective.plusSeconds(5), Duration.ofDays(1));
        var stillOkOnV0 = harness.verificationService().verify(
                new ArtifactRef(CONTENT), postRevoked, v0, effective.plusSeconds(10));
        assertEquals("key-a", stillOkOnV0.key().keyId());
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.verificationService().verify(
                        new ArtifactRef(CONTENT), postRevoked, v1, effective.plusSeconds(10)));
        assertEquals("REJECT_KEY_REVOKED", ex.code().name());
    }

    @Test
    @DisplayName("拒绝倒填吊销：生效时间早于登记时间 → REJECT_BAD_REQUEST")
    void backdatingRejected() {
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.adminService().revoke(
                        "key-a", clock.instant().minus(Duration.ofDays(1)), "backdated"));
        assertEquals("REJECT_BAD_REQUEST", ex.code().name());
        assertEquals(0, harness.revocationLedger().findAll().size());
    }

    @Test
    @DisplayName("未知密钥吊销 → REJECT_KEY_UNKNOWN")
    void revokeUnknownKey() {
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.adminService().revoke("key-nope", clock.instant(), "x"));
        assertEquals("REJECT_KEY_UNKNOWN", ex.code().name());
    }
}

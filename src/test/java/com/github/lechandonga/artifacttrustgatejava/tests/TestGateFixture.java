package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.config.GateProperties;
import com.github.lechandonga.artifacttrustgatejava.crypto.AttestationService;
import com.github.lechandonga.artifacttrustgatejava.policy.PolicyDocument;
import com.github.lechandonga.artifacttrustgatejava.policy.PolicyEngine;
import com.github.lechandonga.artifacttrustgatejava.service.AdmissionService;
import com.github.lechandonga.artifacttrustgatejava.service.AttestationIssuer;
import com.github.lechandonga.artifacttrustgatejava.store.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.store.LocalGateStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * 不启动 Web 容器的轻量测试夹具：本地临时目录 + 真实组件装配。
 */
public final class TestGateFixture {

    public static final long V1_FROM = Instant.parse("2024-01-01T00:00:00Z").toEpochMilli();
    public static final long V2_FROM = Instant.parse("2026-01-01T00:00:00Z").toEpochMilli();

    public final LocalGateStore store;
    public final AttestationService signatures;
    public final AttestationIssuer issuer;
    public final AdmissionService admission;

    private TestGateFixture(LocalGateStore store, AttestationService signatures,
                            AttestationIssuer issuer, AdmissionService admission) {
        this.store = store;
        this.signatures = signatures;
        this.issuer = issuer;
        this.admission = admission;
    }

    public static TestGateFixture create() throws Exception {
        Path dataDir = Files.createTempDirectory("gate-test-");
        GateProperties properties = new GateProperties();
        properties.setDataDir(dataDir.toString());
        LocalGateStore store = new LocalGateStore(properties);
        store.initDirs();
        AttestationService signatures = new AttestationService();
        PolicyEngine policyEngine = new PolicyEngine(store);
        AttestationIssuer issuer = new AttestationIssuer(store, signatures);
        AdmissionService admission = new AdmissionService(store, signatures, policyEngine);
        TestGateFixture fixture = new TestGateFixture(store, signatures, issuer, admission);
        fixture.seed();
        return fixture;
    }

    private void seed() throws Exception {
        long year = 365L * 24 * 3600 * 1000L;
        long now = System.currentTimeMillis();
        putKey("key-team-a", now - 10 * year, now + 10 * year);
        putKey("key-team-b", now - 10 * year, now + 10 * year);
        putKey("key-legacy", now - 10 * year, now - year);

        store.putPolicy("1", new PolicyDocument("1", V1_FROM, "DENY", List.of(
                new PolicyDocument.Rule("reject-untrusted-issuer", "DENY", List.of(
                        new PolicyDocument.Constraint("issuerEquals", "untrusted"))),
                new PolicyDocument.Rule("allow-team-a-release", "ALLOW", List.of(
                        new PolicyDocument.Constraint("artifactTypeEquals", "release"),
                        new PolicyDocument.Constraint("keyIdIn", List.of("key-team-a")),
                        new PolicyDocument.Constraint("maxArtifactSize", 4096),
                        new PolicyDocument.Constraint("requireSigned", true)))
        )));
        store.putPolicy("2", new PolicyDocument("2", V2_FROM, "DENY", List.of(
                new PolicyDocument.Rule("reject-untrusted-issuer", "DENY", List.of(
                        new PolicyDocument.Constraint("issuerEquals", "untrusted"))),
                new PolicyDocument.Rule("allow-team-a-release", "ALLOW", List.of(
                        new PolicyDocument.Constraint("artifactTypeEquals", "release"),
                        new PolicyDocument.Constraint("keyIdIn", List.of("key-team-a")),
                        new PolicyDocument.Constraint("maxArtifactSize", 4096),
                        new PolicyDocument.Constraint("requireSigned", true))),
                new PolicyDocument.Rule("allow-team-b-release", "ALLOW", List.of(
                        new PolicyDocument.Constraint("artifactTypeEquals", "release"),
                        new PolicyDocument.Constraint("keyIdIn", List.of("key-team-b")),
                        new PolicyDocument.Constraint("maxArtifactSize", 4096),
                        new PolicyDocument.Constraint("issuerEquals", "team-b-ci"),
                        new PolicyDocument.Constraint("requireSigned", true)))
        )));
    }

    public void putKey(String keyId, long validFrom, Long validUntil) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        store.putKey(new KeyMaterial(keyId, publicKey, privateKey,
                validFrom, validUntil, null, null));
    }

    /** 重新生成一把全新的同名密钥（清除吊销状态），保证用例相互独立。 */
    public void resetKey(String keyId) throws Exception {
        long year = 365L * 24 * 3600 * 1000L;
        long now = System.currentTimeMillis();
        putKey(keyId, now - 10 * year, now + 10 * year);
    }
}

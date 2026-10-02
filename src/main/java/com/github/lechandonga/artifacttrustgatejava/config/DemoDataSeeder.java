package com.github.lechandonga.artifacttrustgatejava.config;

import com.github.lechandonga.artifacttrustgatejava.policy.PolicyDocument;
import com.github.lechandonga.artifacttrustgatejava.store.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.store.LocalGateStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * 初始化本地演示材料（仅当对应文件不存在时写入，绝不覆盖已存在的密钥/吊销/策略）：
 *  - key-team-a / key-team-b：两把当前有效的 EC 密钥
 *  - key-legacy：一把已到期密钥，用于边界验证
 *  - policy v1（2024-01-01 生效）/ v2（2026-01-01 生效）
 */
@Component
public class DemoDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    public static final long POLICY_V1_FROM = Instant.parse("2024-01-01T00:00:00Z").toEpochMilli();
    public static final long POLICY_V2_FROM = Instant.parse("2026-01-01T00:00:00Z").toEpochMilli();

    private final LocalGateStore store;
    private final GateProperties properties;

    public DemoDataSeeder(LocalGateStore store, GateProperties properties) {
        this.store = store;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!properties.isSeedDemoData()) {
            return;
        }
        long year = 365L * 24 * 3600 * 1000;
        long now = System.currentTimeMillis();
        seedKey("key-team-a", now - 365L * 2 * year, now + 10L * year, null, null);
        seedKey("key-team-b", now - year, now + 10L * year, null, null);
        seedKey("key-legacy", now - 10L * year, now - year, null, null);

        seedPolicy("1", POLICY_V1_FROM, "DENY", List.of(
                new PolicyDocument.Rule("reject-untrusted-issuer", "DENY", List.of(
                        new PolicyDocument.Constraint("issuerEquals", "untrusted"))),
                new PolicyDocument.Rule("allow-team-a-release", "ALLOW", List.of(
                        new PolicyDocument.Constraint("artifactTypeEquals", "release"),
                        new PolicyDocument.Constraint("keyIdIn", List.of("key-team-a")),
                        new PolicyDocument.Constraint("maxArtifactSize", 4096),
                        new PolicyDocument.Constraint("requireSigned", true)))
        ));

        seedPolicy("2", POLICY_V2_FROM, "DENY", List.of(
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
        ));
    }

    private void seedKey(String keyId, long validFrom, Long validUntil,
                         Long revokedAt, String reason) throws Exception {
        if (store.findKey(keyId).isPresent()) {
            return;
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        store.putKey(new KeyMaterial(keyId, publicKey, privateKey,
                validFrom, validUntil, revokedAt, reason));
        log.info("已初始化演示密钥: {}", keyId);
    }

    private void seedPolicy(String version, long effectiveFrom, String defaultEffect,
                            List<PolicyDocument.Rule> rules) {
        if (store.policyPath(version).isPresent()) {
            return;
        }
        store.putPolicy(version, new PolicyDocument(version, effectiveFrom,
                defaultEffect, rules));
        log.info("已初始化策略版本: v{} (effectiveFrom={})", version,
                Instant.ofEpochMilli(effectiveFrom));
    }
}

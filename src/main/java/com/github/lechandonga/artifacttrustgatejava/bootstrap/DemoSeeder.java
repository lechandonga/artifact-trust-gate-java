package com.github.lechandonga.artifacttrustgatejava.bootstrap;

import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyRule;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyVersion;
import com.github.lechandonga.artifacttrustgatejava.service.AdminService;
import com.github.lechandonga.artifacttrustgatejava.service.AttestationService;
import com.github.lechandonga.artifacttrustgatejava.store.KeyStore;
import com.github.lechandonga.artifacttrustgatejava.store.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * 首次启动时生成本地演示材料：
 * - key-a（正常密钥）、key-b（用于轮换/吊销实验）；
 * - 一份对示例制品的合法证明（写入 demo-artifact.json / demo-attestation.json）；
 * - 策略 v1：key-a 放行，其他密钥默认拒绝。
 * 数据目录已存在内容时不重复生成。
 */
@Component
public class DemoSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoSeeder.class);

    public static final String DEMO_CONTENT = """
            {
              "name": "payment-service",
              "version": "2.3.1",
              "builder": "local-demo",
              "files": [
                { "path": "app.jar", "sha256": "9f2d4a77c1b54e8a9e0d6f3b2a1c7d5e" }
              ]
            }
            """;

    private final AdminService adminService;
    private final AttestationService attestationService;
    private final KeyStore keyStore;
    private final PolicyStore policyStore;
    private final String dataDir;

    public DemoSeeder(AdminService adminService, AttestationService attestationService,
                      KeyStore keyStore, PolicyStore policyStore,
                      @Value("${trustgate.data-dir:./data}") String dataDir) {
        this.adminService = adminService;
        this.attestationService = attestationService;
        this.keyStore = keyStore;
        this.policyStore = policyStore;
        this.dataDir = dataDir;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Path dir = Path.of(dataDir);
        Path marker = dir.resolve(".seeded");
        if (Files.exists(marker)) {
            log.info("[Seeder] 数据目录已初始化，跳过演示数据生成: {}", dir.toAbsolutePath());
            return;
        }
        Files.createDirectories(dir);

        KeyMaterial keyA = adminService.generateKey("key-a");
        adminService.generateKey("key-b");
        log.info("[Seeder] 生成演示密钥 key-a / key-b（PEM 保存在 keys.json）");

        String digest = Digests.artifactDigest(DEMO_CONTENT);
        Attestation attestation = attestationService.issue(
                keyA.keyId(), digest, Duration.ofDays(365));
        Files.writeString(dir.resolve("demo-artifact.json"), DEMO_CONTENT);
        Files.writeString(dir.resolve("demo-attestation.json"),
                """
                {
                  "artifact": { "contentJson": %s },
                  "attestation": {
                    "attestationId": "%s",
                    "subjectDigest": "%s",
                    "keyId": "%s",
                    "issuedAt": "%s",
                    "expiresAt": "%s",
                    "signature": "%s"
                  }
                }
                """.formatted(
                        writeJsonString(DEMO_CONTENT),
                        attestation.attestationId(),
                        attestation.subjectDigest(),
                        attestation.keyId(),
                        attestation.issuedAt(),
                        attestation.expiresAt(),
                        attestation.signature()));

        adminService.publishPolicy(List.of(
                new PolicyRule("allow-key-a", "key-a", true, "生产密钥 key-a 签名的制品允许准入"),
                new PolicyRule("default-deny", null, false, "默认拒绝：非信任密钥")));
        log.info("[Seeder] 发布策略 v1: allow-key-a / default-deny");

        Files.writeString(marker, "seeded\n");
        log.info("[Seeder] 演示数据就绪: {} (制品指纹={})", dir.toAbsolutePath(), digest);
    }

    private static String writeJsonString(String raw) {
        String escaped = raw.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
        return "\"" + escaped + "\"";
    }
}

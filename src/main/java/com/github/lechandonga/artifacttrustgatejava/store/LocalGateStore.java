package com.github.lechandonga.artifacttrustgatejava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.github.lechandonga.artifacttrustgatejava.config.GateProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * 基于本地文件的存储：
 * <pre>
 *   {dataDir}/keys/{keyId}.json
 *   {dataDir}/policies/policy-v{n}.json
 *   {dataDir}/audit/decision-{requestId}.json
 * </pre>
 * 全部原子写（临时文件 + ATOMIC_MOVE），保证并发下文件不会写花。
 */
@Component
public class LocalGateStore {

    private static final Logger log = LoggerFactory.getLogger(LocalGateStore.class);

    private final ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final GateProperties properties;
    private Path keysDir;
    private Path policiesDir;
    private Path auditDir;

    public LocalGateStore(GateProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void initDirs() throws IOException {
        Path root = Path.of(properties.getDataDir());
        keysDir = Files.createDirectories(root.resolve("keys"));
        policiesDir = Files.createDirectories(root.resolve("policies"));
        auditDir = Files.createDirectories(root.resolve("audit"));
        log.info("本地准入服务数据目录: {}", root.toAbsolutePath());
    }

    // ---- keys ----

    public synchronized void putKey(KeyMaterial key) {
        writeJson(keysDir.resolve(key.keyId() + ".json"), key);
    }

    public Optional<KeyMaterial> findKey(String keyId) {
        Path path = keysDir.resolve(keyId + ".json");
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        return Optional.of(readJson(path, KeyMaterial.class));
    }

    // ---- policies ----

    public synchronized void putPolicy(String version, Object policy) {
        writeJson(policiesDir.resolve("policy-" + version + ".json"), policy);
    }

    public Optional<Path> policyPath(String version) {
        Path path = policiesDir.resolve("policy-" + version + ".json");
        return Files.exists(path) ? Optional.of(path) : Optional.empty();
    }

    /** 列出所有策略文件（按版本号目录序，文件名即版本）。 */
    public List<Path> listPolicyPaths() {
        try (Stream<Path> stream = Files.list(policiesDir)) {
            return stream.filter(p -> p.getFileName().toString().startsWith("policy-"))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ---- audit ----

    public boolean auditExists(String requestId) {
        return Files.exists(auditDir.resolve("decision-" + requestId + ".json"));
    }

    public Path writeAuditIfAbsent(String requestId, Object decision) {
        Path target = auditDir.resolve("decision-" + requestId + ".json");
        Path tmp = auditDir.resolve(".tmp-" + requestId + "-" + Thread.currentThread().getId());
        try {
            Files.writeString(tmp, mapper.writeValueAsString(decision), StandardCharsets.UTF_8);
            try {
                Files.move(tmp, target, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
                return target;
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                synchronized (target.toString().intern()) {
                    if (Files.exists(target)) {
                        Files.deleteIfExists(tmp);
                        return target;
                    }
                    Files.move(tmp, target);
                    return target;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

 public Optional<Object> readAudit(String requestId, Class<?> type) {
        Path path = auditDir.resolve("decision-" + requestId + ".json");
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        return Optional.of(readJson(path, type));
    }

    // ---- helpers ----

    private void writeJson(Path path, Object value) {
        try {
            Path tmp = path.resolveSibling(".tmp-" + path.getFileName());
            Files.writeString(tmp, mapper.writeValueAsString(value), StandardCharsets.UTF_8);
            Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private <T> T readJson(Path path, Class<T> type) {
        try {
            return mapper.readValue(Files.readString(path, StandardCharsets.UTF_8), type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}

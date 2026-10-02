package com.github.lechandonga.artifacttrustgatejava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.model.AuditRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 审计仓库：audit.json，仅追加。按幂等键去重，
 * 重复提交返回同一条记录，不产生第二条审计。
 */
@Component
public class AuditStore {

    private final ObjectMapper mapper;
    private final Path file;

    public AuditStore(ObjectMapper mapper, @Value("${trustgate.data-dir:./data}") String dataDir) {
        this.mapper = mapper;
        this.file = Path.of(dataDir, "audit.json");
    }

    public synchronized List<AuditRecord> findAll() {
        return load();
    }

    public synchronized Optional<AuditRecord> findByIdempotencyKey(String key) {
        return load().stream().filter(r -> r.idempotencyKey().equals(key)).findFirst();
    }

    public synchronized AuditRecord appendIfAbsent(AuditRecord record) {
        List<AuditRecord> all = load();
        Optional<AuditRecord> existing = all.stream()
                .filter(r -> r.idempotencyKey().equals(record.idempotencyKey()))
                .findFirst();
        if (existing.isPresent()) {
            return existing.get();
        }
        all.add(record);
        JsonFiles.write(mapper, file, all);
        return record;
    }

    private List<AuditRecord> load() {
        if (!Files.exists(file)) {
            return new ArrayList<>();
        }
        try {
            List<AuditRecord> list = mapper.readValue(Files.readString(file),
                    new TypeReference<>() {
                    });
            return new ArrayList<>(list);
        } catch (Exception e) {
            throw new IllegalStateException("加载审计仓库失败: " + file, e);
        }
    }
}

package com.github.lechandonga.artifacttrustgatejava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
import com.github.lechandonga.artifacttrustgatejava.model.Revocation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 吊销账本：revocations.json，仅追加。条目数即快照版本号，
 * 因此“按版本复现”就是取账本前 N 条；后来新增的吊销不会改写历史快照。
 */
@Component
public class RevocationLedger {

    private final ObjectMapper mapper;
    private final Path file;

    public RevocationLedger(ObjectMapper mapper, @Value("${trustgate.data-dir:./data}") String dataDir) {
        this.mapper = mapper;
        this.file = Path.of(dataDir, "revocations.json");
    }

    public synchronized List<Revocation> findAll() {
        return load();
    }

    public synchronized KeyBookSnapshot latestSnapshot(Instant now) {
        List<Revocation> all = load();
        return new KeyBookSnapshot(all.size(), now, List.copyOf(all));
    }

    /**
     * 取版本 version（=前 version 条吊销记录）。版本不可变，天然支持历史复现。
     */
    public synchronized KeyBookSnapshot snapshotAt(int version) {
        List<Revocation> all = load();
        if (version < 0 || version > all.size()) {
            return null;
        }
        List<Revocation> slice = List.copyOf(all.subList(0, version));
        return new KeyBookSnapshot(version, null, slice);
    }

    public synchronized KeyBookSnapshot append(Revocation revocation) {
        List<Revocation> all = load();
        all.add(revocation);
        JsonFiles.write(mapper, file, all);
        return new KeyBookSnapshot(all.size(), revocation.recordCreatedAt(), List.copyOf(all));
    }

    private List<Revocation> load() {
        if (!Files.exists(file)) {
            return new ArrayList<>();
        }
        try {
            List<Revocation> list = mapper.readValue(Files.readString(file),
                    new TypeReference<>() {
                    });
            return new ArrayList<>(list);
        } catch (Exception e) {
            throw new IllegalStateException("加载吊销账本失败: " + file, e);
        }
    }
}

package com.github.lechandonga.artifacttrustgatejava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyVersion;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 策略仓库：policies.json。策略版本仅追加、不可修改，
 * 同一制品在不同策略版本下的判定可分别复现。
 */
@Component
public class PolicyStore {

    private final ObjectMapper mapper;
    private final Path file;

    public PolicyStore(ObjectMapper mapper, @Value("${trustgate.data-dir:./data}") String dataDir) {
        this.mapper = mapper;
        this.file = Path.of(dataDir, "policies.json");
    }

    public synchronized List<PolicyVersion> findAll() {
        return load();
    }

    public synchronized Optional<PolicyVersion> find(int version) {
        return load().stream().filter(p -> p.version() == version).findFirst();
    }

    public synchronized Optional<PolicyVersion> latest() {
        return load().stream().reduce((first, second) -> second);
    }

    public synchronized PolicyVersion append(PolicyVersion policyVersion) {
        List<PolicyVersion> all = load();
        if (all.stream().anyMatch(p -> p.version() == policyVersion.version())) {
            throw new IllegalStateException("策略版本已存在且不可变: v" + policyVersion.version());
        }
        all.add(policyVersion);
        JsonFiles.write(mapper, file, all);
        return policyVersion;
    }

    private List<PolicyVersion> load() {
        if (!Files.exists(file)) {
            return new ArrayList<>();
        }
        try {
            List<PolicyVersion> list = mapper.readValue(Files.readString(file),
                    new TypeReference<>() {
                    });
            return new ArrayList<>(list);
        } catch (Exception e) {
            throw new IllegalStateException("加载策略仓库失败: " + file, e);
        }
    }
}

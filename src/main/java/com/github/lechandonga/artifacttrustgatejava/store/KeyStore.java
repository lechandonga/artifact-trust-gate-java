package com.github.lechandonga.artifacttrustgatejava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.model.KeyMaterial;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 密钥材料仓库：keys.json。密钥一经登记不可删除（轮换只标记 replacedBy）。
 */
@Component
public class KeyStore {

    private final ObjectMapper mapper;
    private final Path file;

    public KeyStore(ObjectMapper mapper, @Value("${trustgate.data-dir:./data}") String dataDir) {
        this.mapper = mapper;
        this.file = Path.of(dataDir, "keys.json");
    }

    public synchronized List<KeyMaterial> findAll() {
        return load();
    }

    public synchronized Optional<KeyMaterial> find(String keyId) {
        return load().stream().filter(k -> k.keyId().equals(keyId)).findFirst();
    }

    public synchronized KeyMaterial save(KeyMaterial key) {
        List<KeyMaterial> keys = load();
        keys.removeIf(k -> k.keyId().equals(key.keyId()));
        keys.add(key);
        persist(keys);
        return key;
    }

    private List<KeyMaterial> load() {
        if (!java.nio.file.Files.exists(file)) {
            return new ArrayList<>();
        }
        try {
            List<KeyMaterial> keys = mapper.readValue(
                    java.nio.file.Files.readString(file), new TypeReference<>() {
                    });
            return new ArrayList<>(keys);
        } catch (Exception e) {
            throw new IllegalStateException("加载密钥仓库失败: " + file, e);
        }
    }

    private void persist(List<KeyMaterial> keys) {
        JsonFiles.write(mapper, file, keys);
    }
}

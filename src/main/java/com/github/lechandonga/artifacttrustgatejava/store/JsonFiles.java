package com.github.lechandonga.artifacttrustgatejava.store;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * JSON 文件读写：原子移动写入，避免并发/崩溃时出现半条记录。
 */
public final class JsonFiles {

    private JsonFiles() {
    }

    public static <T> T read(ObjectMapper mapper, Path file, Class<T> type, T fallback) {
        if (!Files.exists(file)) {
            return fallback;
        }
        try {
            return mapper.readValue(Files.readString(file, StandardCharsets.UTF_8), type);
        } catch (IOException e) {
            throw new UncheckedIOException("读取数据文件失败: " + file, e);
        }
    }

    public static void write(ObjectMapper mapper, Path file, Object value) {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(value);
            Files.writeString(tmp, json, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("写入数据文件失败: " + file, e);
        }
    }
}

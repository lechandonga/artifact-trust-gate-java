package com.github.lechandonga.artifacttrustgatejava.crypto;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

/**
 * 规范化 JSON（遵循 RFC 8785 JCS 核心规则）：
 * 对象字段按 UTF-16 码元升序排列；数组保持顺序；去除一切无意义空白；
 * 字符串统一转义；数字按规范序列化。
 *
 * 同一份逻辑内容即使字段顺序或空白不同，规范化结果（及其摘要）也完全一致。
 */
public final class JsonCanonicalizer {

    private static final JsonFactory FACTORY = new JsonFactory();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonCanonicalizer() {
    }

    public static byte[] canonicalize(String json) {
        Object value = parse(json);
        StringBuilder out = new StringBuilder();
        writeValue(value, out);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String sha256Hex(String json) {
        return Hex.encode(sha256(canonicalize(json)));
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256HexBytes(byte[] data) {
        return Hex.encode(sha256(data));
    }

    public static Object readTreeAsObject(String json) throws IOException {
        return MAPPER.readValue(json, Object.class);
    }

    private static Object parse(String json) {
        try (JsonParser parser = FACTORY.createParser(json)) {
            JsonToken token = parser.nextToken();
            if (token == null) {
                throw new IllegalArgumentException("空内容");
            }
            Object value = readToken(parser, token);
            if (parser.nextToken() != null) {
                throw new IllegalArgumentException("JSON 根节点后存在多余内容");
            }
            return value;
        } catch (IOException e) {
            throw new IllegalArgumentException("非法 JSON: " + e.getMessage(), e);
        }
    }

    private static Object readToken(JsonParser parser, JsonToken token) throws IOException {
        return switch (token) {
            case START_OBJECT -> {
                TreeMap<String, Object> map = new TreeMap<>();
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    String name = parser.currentName();
                    JsonToken valueToken = parser.nextToken();
                    map.put(name, readToken(parser, valueToken));
                }
                yield map;
            }
            case START_ARRAY -> {
                ArrayList<Object> list = new ArrayList<>();
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    list.add(readToken(parser, parser.currentToken()));
                }
                yield list;
            }
            case VALUE_STRING -> parser.getText();
            case VALUE_TRUE -> Boolean.TRUE;
            case VALUE_FALSE -> Boolean.FALSE;
            case VALUE_NULL -> null;
            case VALUE_NUMBER_INT -> parser.getLongValue();
            case VALUE_NUMBER_FLOAT -> new BigDecimal(parser.getText()).stripTrailingZeros();
            default -> throw new IllegalArgumentException("不支持的 JSON token: " + token);
        };
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof Boolean b) {
            out.append(b.booleanValue() ? "true" : "false");
        } else if (value instanceof String s) {
            writeString(s, out);
        } else if (value instanceof Long l) {
            out.append(l.toString());
        } else if (value instanceof Integer i) {
            out.append(i.toString());
        } else if (value instanceof BigDecimal bd) {
            out.append(bd.stripTrailingZeros().toPlainString());
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) map).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(entry.getKey(), out);
                out.append(':');
                writeValue(entry.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            out.append('[');
            boolean first = true;
            for (Object item : iterable) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeValue(item, out);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("无法规范化类型: " + value.getClass());
        }
    }

    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}

package com.github.lechandonga.artifacttrustgatejava.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * JCS 风格的 JSON 规范化（RFC 8785 思路的本地简化实现）：
 * 对象成员按键名字典序排列；数组保持顺序；去除所有无意义空白；
 * 字符串按 JSON 规则转义；数字使用 Jackson 解析后的标准形式输出。
 * 同一份内容在字段顺序、缩进、换行差异下得到完全相同的字节序列。
 */
public final class JsonCanonicalizer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonCanonicalizer() {
    }

    public static byte[] canonicalize(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeNode(root, out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalArgumentException("非法 JSON，无法规范化: " + e.getMessage(), e);
        }
    }

    public static String canonicalString(String json) {
        return new String(canonicalize(json), StandardCharsets.UTF_8);
    }

    private static void writeNode(JsonNode node, ByteArrayOutputStream out) throws IOException {
        JsonNodeType type = node.getNodeType();
        switch (type) {
            case OBJECT -> {
                Map<String, JsonNode> sorted = new TreeMap<>();
                node.fields().forEachRemaining(e -> sorted.put(e.getKey(), e.getValue()));
                out.write('{');
                boolean first = true;
                for (Map.Entry<String, JsonNode> e : sorted.entrySet()) {
                    if (!first) {
                        out.write(',');
                    }
                    first = false;
                    writeJsonString(e.getKey(), out);
                    out.write(':');
                    writeNode(e.getValue(), out);
                }
                out.write('}');
            }
            case ARRAY -> {
                out.write('[');
                for (int i = 0; i < node.size(); i++) {
                    if (i > 0) {
                        out.write(',');
                    }
                    writeNode(node.get(i), out);
                }
                out.write(']');
            }
            case STRING -> writeJsonString(node.asText(), out);
            case BOOLEAN -> out.write(node.asBoolean() ? "true".getBytes(StandardCharsets.UTF_8)
                    : "false".getBytes(StandardCharsets.UTF_8));
            case NULL -> out.write("null".getBytes(StandardCharsets.UTF_8));
            case NUMBER -> {
                if (node.isIntegralNumber()) {
                    out.write(String.valueOf(node.longValue()).getBytes(StandardCharsets.UTF_8));
                } else if (node.isFloatingPointNumber()) {
                    out.write(canonicalDouble(node.doubleValue()).getBytes(StandardCharsets.UTF_8));
                } else {
                    out.write(node.decimalValue().stripTrailingZeros().toPlainString()
                            .getBytes(StandardCharsets.UTF_8));
                }
            }
            default -> throw new IllegalArgumentException("不支持的 JSON 节点类型: " + type);
        }
    }

    private static String canonicalDouble(double value) {
        if (value == 0.0d) {
            return Double.doubleToRawLongBits(value) < 0 ? "-0" : "0";
        }
        if (Double.isInfinite(value) || Double.isNaN(value)) {
            throw new IllegalArgumentException("JSON 不允许 NaN/Infinity");
        }
        // 最短可往返表示，保证同一数值的不同写法（1.0 / 1 / 1.00）规范化一致
        double reparsed = Double.parseDouble(Double.toString(value));
        if (reparsed == Math.rint(reparsed) && Math.abs(value) < 1e16) {
            return Long.toString((long) reparsed);
        }
        return Double.toString(value);
    }

    private static void writeJsonString(String value, ByteArrayOutputStream out) throws IOException {
        ByteArrayOutputStream str = new ByteArrayOutputStream();
        str.write('"');
        int[] codepoints = value.codePoints().toArray();
        for (int cp : codepoints) {
            switch (cp) {
                case '"' -> {
                    str.write('\\');
                    str.write('"');
                }
                case '\\' -> {
                    str.write('\\');
                    str.write('\\');
                }
                case '\b' -> str.write("\\b".getBytes(StandardCharsets.UTF_8));
                case '\f' -> str.write("\\f".getBytes(StandardCharsets.UTF_8));
                case '\n' -> str.write("\\n".getBytes(StandardCharsets.UTF_8));
                case '\r' -> str.write("\\r".getBytes(StandardCharsets.UTF_8));
                case '\t' -> str.write("\\t".getBytes(StandardCharsets.UTF_8));
                default -> {
                    if (cp < 0x20) {
                        str.write(String.format("\\u%04x", cp).getBytes(StandardCharsets.UTF_8));
                    } else {
                        str.write(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
        }
        str.write('"');
        out.write(str.toByteArray());
    }
}

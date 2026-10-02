package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 业务：制品规范化——无意义差异不影响摘要，内容差异必须体现在摘要上。
 */
class CanonicalizationTest {

    private static final Logger log = LoggerFactory.getLogger(CanonicalizationTest.class);

    @Test
 @DisplayName("规范化-字段顺序与空白差异：摘要一致")
    void fieldOrderAndWhitespaceAreInsignificant() {
        String compact = "{\"type\":\"release\",\"name\":\"app\",\"version\":\"1.0.0\"}";
        String reordered = "{\n  \"version\": \"1.0.0\",\n  \"name\": \"app\",\n  \"type\": \"release\"\n}";
        String padded = " { \"type\" : \"release\" , \"name\" : \"app\" , \"version\" : \"1.0.0\" } ";

        String d1 = JsonCanonicalizer.sha256Hex(compact);
        String d2 = JsonCanonicalizer.sha256Hex(reordered);
        String d3 = JsonCanonicalizer.sha256Hex(padded);
        log.info("[规范化] 业务=无意义差异不影响摘要 | 结果: {} == {} == {} -> PASS", d1, d2, d3);
        assertEquals(d1, d2);
        assertEquals(d1, d3);
    }

    @Test
    @DisplayName("规范化-内容篡改：摘要必须不同")
    void contentChangeChangesDigest() {
        String original = "{\"type\":\"release\",\"name\":\"app\",\"version\":\"1.0.0\"}";
        String tampered = "{\"type\":\"release\",\"name\":\"app\",\"version\":\"1.0.1\"}";
        assertNotEquals(JsonCanonicalizer.sha256Hex(original),
                JsonCanonicalizer.sha256Hex(tampered));
        log.info("[规范化] 业务=内容被篡改时摘要变化 | 结果: PASS");
    }

    @Test
    @DisplayName("规范化-数字与嵌套结构：1.0/100 等无意义写法归一")
    void numbersAndNestedStructures() {
        String a = "{\"b\":[1, 2.0, {\"z\":1,\"a\":2}],\"n\":100}";
        String b = "{\"n\":1.0e2,\"b\":[1,2.000,{\"a\":2,\"z\":1}]}";
        assertEquals(JsonCanonicalizer.sha256Hex(a), JsonCanonicalizer.sha256Hex(b));
        log.info("[规范化] 业务=数字/嵌套结构等价归一 | 结果: PASS");
    }

    @Test
    @DisplayName("规范化-非法 JSON：抛出明确异常")
    void malformedJsonRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> JsonCanonicalizer.canonicalize("{not-json}"));
        assertThrows(IllegalArgumentException.class,
                () -> JsonCanonicalizer.sha256Hex("{\"a\":}"));
        log.info("[规范化] 业务=非法制品被识别 | 结果: PASS");
    }
}

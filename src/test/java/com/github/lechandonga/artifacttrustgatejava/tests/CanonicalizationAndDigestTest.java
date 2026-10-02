package com.github.lechandonga.artifacttrustgatejava.tests;

import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer;
import com.github.lechandonga.artifacttrustgatejava.tests.support.BusinessLoggingExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 业务覆盖：制品规范化指纹——同内容不同写法结论一致，真实改动指纹变化。
 */
@DisplayName("制品指纹与 JSON 规范化")
@ExtendWith(BusinessLoggingExtension.class)
class CanonicalizationAndDigestTest {

    @Nested
    @DisplayName("无意义差异不影响结论")
    class EquivalentForms {

        @Test
        @DisplayName("字段顺序不同 → 同一指纹")
        void fieldOrder() {
            String a = "{\"name\":\"svc\",\"version\":\"1.0\"}";
            String b = "{\n  \"version\": \"1.0\",\n  \"name\": \"svc\"\n}";
            assertEquals(Digests.artifactDigest(a), Digests.artifactDigest(b));
        }

        @Test
        @DisplayName("缩进/空白/换行不同 → 同一指纹")
        void whitespace() {
            String compact = "{\"a\":1,\"b\":[true,null,\"x\"]}";
            String pretty = " {\n\t\"a\": 1,\n\t\"b\":[ true, null, \"x\" ]\n}\n";
            assertEquals(Digests.artifactDigest(compact), Digests.artifactDigest(pretty));
        }

        @Test
        @DisplayName("嵌套对象字段也按键名排序 → 同一规范化字节")
        void nestedOrdering() {
            String a = "{\"outer\":{\"z\":1,\"a\":2},\"k\":[3,2,1]}";
            String b = "{\"k\":[3,2,1],\"outer\":{\"a\":2,\"z\":1}}";
            assertEquals(JsonCanonicalizer.canonicalString(a),
                    JsonCanonicalizer.canonicalString(b));
            assertEquals("{\"k\":[3,2,1],\"outer\":{\"a\":2,\"z\":1}}",
                    JsonCanonicalizer.canonicalString(a));
        }
    }

    @Nested
    @DisplayName("有意义差异必须被识别")
    class MeaningfulChanges {

        @Test
        @DisplayName("字段值被改动 → 指纹不同（篡改检测基础）")
        void valueChanged() {
            String a = "{\"name\":\"svc\",\"version\":\"1.0\"}";
            String tampered = "{\"name\":\"svc\",\"version\":\"1.1\"}";
            assertNotEquals(Digests.artifactDigest(a), Digests.artifactDigest(tampered));
        }

        @Test
        @DisplayName("数组顺序属于内容的一部分 → 指纹不同")
        void arrayOrder() {
            String a = "{\"files\":[\"a\",\"b\"]}";
            String b = "{\"files\":[\"b\",\"a\"]}";
            assertNotEquals(Digests.artifactDigest(a), Digests.artifactDigest(b));
        }
    }
}

package com.github.lechandonga.artifacttrustgatejava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

/**
 * 冒烟：Spring 上下文（含 seeder、全部仓库与服务）能在本地数据目录正常装配启动。
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT,
        properties = "trustgate.data-dir=target/smoke-data")
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}

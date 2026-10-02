package com.github.lechandonga.artifacttrustgatejava.tests.support;

import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 让测试日志直接体现“覆盖了哪个业务点、结果如何”：
 * 每个用例开始/结束打印业务名称（@DisplayName）与通过/失败结论。
 */
public class BusinessLoggingExtension implements BeforeTestExecutionCallback, AfterTestExecutionCallback {

    private static final Logger log = LoggerFactory.getLogger("BUSINESS-TEST");

    @Override
    public void beforeTestExecution(ExtensionContext context) {
        log.info("▶ 开始用例 [{}] {}", context.getDisplayName(), businessTag(context));
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        boolean failed = context.getExecutionException().isPresent();
        log.info("{} 用例 [{}] {} {}", failed ? "✖ 失败" : "✔ 通过",
                context.getDisplayName(), businessTag(context), failed ? "（断言未满足/抛异常）" : "");
    }

    private String businessTag(ExtensionContext context) {
        Class<?> testClass = context.getTestClass().orElse(Object.class);
        return " @" + testClass.getSimpleName();
    }
}

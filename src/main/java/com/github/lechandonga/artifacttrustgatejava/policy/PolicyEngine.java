package com.github.lechandonga.artifacttrustgatejava.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lechandonga.artifacttrustgatejava.crypto.JsonCanonicalizer;
import com.github.lechandonga.artifacttrustgatejava.store.LocalGateStore;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * 版本化策略评估：
 * 1) 在指定判定时间点，选取 effectiveFrom <= 该时间 的最新版本（历史复现）；
 * 2) 规则按文件中的顺序逐条匹配，首条命中即决定结论；
 * 3) 全部未命中则使用 defaultEffect。
 */
@Component
public class PolicyEngine {

    private final LocalGateStore store;
    private final ObjectMapper mapper = new ObjectMapper();

    public PolicyEngine(LocalGateStore store) {
        this.store = store;
    }

    public PolicyDocument selectPolicy(long evaluationTime) {
        PolicyDocument selected = null;
        for (Path path : store.listPolicyPaths()) {
            PolicyDocument doc = read(path);
            if (doc.effectiveFrom() <= evaluationTime
                    && (selected == null || doc.effectiveFrom() > selected.effectiveFrom())) {
                selected = doc;
            }
        }
        return selected;
    }

    public PolicyResult evaluate(PolicyDocument policy, PolicyInput input) {
        for (PolicyDocument.Rule rule : policy.rules()) {
            List<PolicyDocument.Constraint> all = rule.all() == null ? List.of() : rule.all();
            if (all.stream().allMatch(c -> matches(c, input))) {
                return new PolicyResult(policy.version(), rule.name(),
                        "ALLOW".equalsIgnoreCase(rule.effect()),
                        "命中规则 [" + rule.name() + "]，动作 " + rule.effect());
            }
        }
        boolean allowDefault = "ALLOW".equalsIgnoreCase(policy.defaultEffect());
        return new PolicyResult(policy.version(), "<default:" + policy.defaultEffect() + ">",
                allowDefault, "无规则命中，使用默认动作 " + policy.defaultEffect());
    }

    private boolean matches(PolicyDocument.Constraint constraint, PolicyInput input) {
        Object expected = constraint.expected();
        return switch (constraint.constraint()) {
            case "issuerEquals" -> expected.equals(input.issuer());
            case "keyIdIn" -> asStringList(expected).contains(input.keyId());
            case "artifactTypeEquals" -> expected.equals(input.artifactType());
            case "maxArtifactSize" -> input.artifactSize() <= ((Number) expected).longValue();
            case "requireSigned" -> Boolean.TRUE.equals(expected) && input.signed();
            default -> throw new IllegalArgumentException("未知策略约束: " + constraint.constraint());
        };
    }

    @SuppressWarnings("unchecked")
    private List<String> asStringList(Object expected) {
        return ((List<Object>) expected).stream().map(String::valueOf).toList();
    }

    private PolicyDocument read(Path path) {
        try {
            return mapper.readValue(path.toFile(), PolicyDocument.class);
        } catch (Exception e) {
            throw new IllegalStateException("策略文件损坏: " + path, e);
        }
    }

    public record PolicyInput(String issuer, String keyId, String artifactType,
                              long artifactSize, boolean signed) {

        public static PolicyInput of(Map<String, Object> artifact, String issuer,
                                     String keyId, int canonicalSize, boolean signed) {
            Object type = artifact.get("type");
            return new PolicyInput(issuer, keyId, type == null ? null : String.valueOf(type),
                    canonicalSize, signed);
        }
    }

    public record PolicyResult(String policyVersion, String matchedRule,
                               boolean allow, String explanation) {
    }
}

package com.github.lechandonga.artifacttrustgatejava.service;

import com.github.lechandonga.artifacttrustgatejava.model.DecisionCode;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyRule;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyVersion;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.store.PolicyStore;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 策略评估：按规则声明顺序 first-match-wins；
 * matchKeyId 匹配签名密钥；matchKeyId 为空串/null 表示兜底默认规则。
 * 没有任何规则命中（含缺少默认规则）时默认拒绝（fail-closed）。
 */
@Service
public class PolicyService {

    private final PolicyStore policyStore;

    public PolicyService(PolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    public PolicyVersion resolve(Integer requestedVersion) {
        if (requestedVersion != null && requestedVersion > 0) {
            return policyStore.find(requestedVersion)
                    .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_POLICY_VERSION_UNKNOWN,
                            "策略版本不存在: v" + requestedVersion));
        }
        return policyStore.latest()
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_POLICY_DENY,
                        "尚未定义任何准入策略，fail-closed 拒绝"));
    }

    public record Match(PolicyRule rule, boolean allowed) {
    }

    public Match evaluate(PolicyVersion policy, String keyId) {
        List<PolicyRule> rules = policy.rules();
        for (PolicyRule rule : rules) {
            if (rule.matchKeyId() == null || rule.matchKeyId().isBlank()) {
                return new Match(rule, rule.allow());
            }
            if (rule.matchKeyId().equals(keyId)) {
                return new Match(rule, rule.allow());
            }
        }
        throw new ServiceException(DecisionCode.REJECT_POLICY_DENY,
                "策略 v" + policy.version() + " 没有匹配密钥 " + keyId
                        + " 的规则且无默认规则，fail-closed 拒绝");
    }
}

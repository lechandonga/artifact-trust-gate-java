package com.github.lechandonga.artifacttrustgatejava.web;

import java.util.List;
import java.util.Map;

/**
 * 准入结论。拒绝时 denyReasons 必须给出可区分的具体原因码。
 */
public record AdmissionDecision(String requestId, String effect, List<String> denyReasons,
                                String artifactDigest, String keyId, String keyState,
                                String policyVersion, String matchedRule,
                                long evaluatedAt, boolean cached,
                                Map<String, String> detail) {
}

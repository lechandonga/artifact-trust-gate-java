package com.github.lechandonga.artifacttrustgatejava.web;

/**
 * 一次准入提交。
 *
 * @param requestId   幂等键：同一 requestId 重复提交返回首次结论，且不重复审计
 * @param artifact    制品 JSON 字符串（本地用字符串模拟制品文件）
 * @param attestation 证明 JSON 字符串（可为空，表示缺少签名材料）
 * @param evaluateAt  指定判定时间（epoch millis），用于历史复现；null 表示当前时间
 */
public record AdmissionRequest(String requestId, String artifact,
                               String attestation, Long evaluateAt) {
}

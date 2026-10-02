package com.github.lechandonga.artifacttrustgatejava.model;

/**
 * 每一个拒绝原因都必须可区分，禁止笼统地归为“校验失败”。
 */
public enum DenyReason {

    MALFORMED_ARTIFACT("制品不是合法 JSON，无法规范化"),
    MALFORMED_ATTESTATION("证明文件不是合法 JSON"),
    MISSING_ATTESTATION("未提交签名证明"),
    INCOMPLETE_SIGNATURE_MATERIAL("签名材料不完整（缺少 keyId / signature / coveredFields 等）"),
    UNKNOWN_KEY("证明引用的密钥不存在"),
    SIGNATURE_MISMATCH("签名与证明内容不匹配"),
    CONTENT_TAMPERED("制品摘要与证明中记录的不一致，内容可能被篡改"),
    KEY_NOT_VALID_YET("签发时密钥尚未生效"),
    KEY_EXPIRED("密钥或证明已超过有效期"),
    KEY_REVOKED("密钥在判定时间点已被吊销"),
    ATTESTATION_NOT_YET_VALID("证明尚未到生效时间"),
    ATTESTATION_EXPIRED("证明已过期"),
    POLICY_DENIED("命中策略拒绝规则或落入默认拒绝"),
    POLICY_NOT_FOUND("在指定时间点找不到可用策略版本"),
    INVALID_REQUEST("请求参数错误");

    private final String description;

    DenyReason(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

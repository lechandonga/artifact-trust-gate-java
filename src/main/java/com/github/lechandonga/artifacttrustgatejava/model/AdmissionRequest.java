package com.github.lechandonga.artifacttrustgatejava.model;

import java.time.Instant;

/**
 * 准入提交请求。
 * evaluationTime 为空表示按当前时间判定；非空表示复现指定历史时刻。
 * policyVersion/keyBookVersion 为空（或 0）表示使用最新版本；
 * 指定版本时按该版本复现历史判定。
 */
public record AdmissionRequest(
        ArtifactRef artifact,
        Attestation attestation,
        Instant evaluationTime,
        Integer policyVersion,
        Integer keyBookVersion
) {
}

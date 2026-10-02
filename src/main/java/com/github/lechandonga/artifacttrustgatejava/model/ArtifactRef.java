package com.github.lechandonga.artifacttrustgatejava.model;

/**
 * 提交校验的制品：内容以 JSON 树形式给出，
 * 规范化（字段排序、去除无意义空白）后计算 SHA-256 指纹。
 */
public record ArtifactRef(String contentJson) {
}

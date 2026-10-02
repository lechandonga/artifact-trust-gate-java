# 本地制品准入校验服务（Artifact Trust Gate）

一套完全本地化的制品准入（admission）校验服务：用本地文件模拟制品、签名证明和密钥材料，
对每次提交给出 **签名校验 → 密钥状态判断 → 策略判定 → 审计落盘** 的完整结论。
不依赖任何外部服务、KMS 或真实凭据；密钥对在本地启动时自动生成。

技术栈：Java 21、Spring Boot 3.4、纯 JDK 加密（EC `secp256r1` + `SHA256withECDSA`）、
Jackson；所有状态保存在本地目录 `gate-data/`（可用 `GATE_DATA_DIR` 覆盖）。

## 1. 目录与运行

```bash
mvn test                 # 运行全部单测（20 个，日志带业务标签与逐用例结果）
mvn spring-boot:run      # 启动服务，默认 8080 端口
# 或
mvn package -DskipTests && java -jar target/artifact-trust-gate-java-1.0-SNAPSHOT.jar
```

首次启动时 `DemoDataSeeder` 会写入（仅在文件不存在时，绝不覆盖吊销记录）：

- 密钥：`key-team-a`、`key-team-b`（长期有效），`key-legacy`（已到期）
- 策略：`policy-v1.json`（2024-01-01 生效）、`policy-v2.json`（2026-01-01 生效）

本地存储布局：

```
gate-data/
├── keys/{keyId}.json           # 公钥/私钥(base64)、生效窗口、吊销记录
├── policies/policy-v{n}.json   # 不可变的版本化策略文件
└── audit/decision-{requestId}.json  # 每个 requestId 一份，只写一次
```

## 2. 校验协议

### 2.1 制品与规范化摘要

制品为 JSON 文本。校验前先按 RFC 8785（JCS）核心规则规范化（`JsonCanonicalizer`）：

- 对象字段按 UTF-16 码元升序排列；数组保持顺序
- 去除所有无意义空白；字符串统一转义；数字归一（如 `1.0` 与 `1` 等价）

制品指纹 = `SHA-256(canonical JSON)`。因此同一份内容在**字段顺序、缩进、空白**差异下
摘要完全一致；任何内容改动必然改变摘要。非法 JSON 直接以 `MALFORMED_ARTIFACT` 拒绝。

### 2.2 证明（attestation）结构

```json
{
  "keyId": "key-team-a",
  "artifactDigest": "sha256 十六进制",
  "notBefore": 1735689600000,
  "notAfter": 1900000000000,
  "issuedAt": 1767312000000,
  "issuer": "team-a-ci",
  "algorithm": "SHA256withECDSA",
  "signature": "base64(ECDSA-P1363)"
}
```

签名覆盖字段固定为 `keyId, artifactDigest, notBefore, notAfter, issuedAt, issuer`
（按该集合的规范化 JSON 签名），`signature`/`algorithm` 自身不在签名载荷内。

### 2.3 判定流水线（拒绝原因严格区分）

顺序检查，每个失败对应独立原因码（可多个同时返回），定义见 `DenyReason`：

| 检查 | 拒绝原因码 |
| --- | --- |
| 制品不是合法 JSON | `MALFORMED_ARTIFACT` |
| 未提交证明 | `MISSING_ATTESTATION` |
| 证明不是合法 JSON | `MALFORMED_ATTESTATION` |
| 缺少 keyId/signature/artifactDigest/时间/issuer | `INCOMPLETE_SIGNATURE_MATERIAL` |
| keyId 在本地密钥库不存在 | `UNKNOWN_KEY` |
| ECDSA 验签失败 | `SIGNATURE_MISMATCH` |
| 制品摘要 ≠ 证明中 artifactDigest | `CONTENT_TAMPERED` |
| 签发时密钥未生效 / 已吊销 / 已过期 | `KEY_NOT_VALID_YET` / `KEY_REVOKED` / `KEY_EXPIRED` |
| 判定时间早于 notBefore / 晚于 notAfter | `ATTESTATION_NOT_YET_VALID` / `ATTESTATION_EXPIRED` |
| 指定时间点无策略 | `POLICY_NOT_FOUND` |
| 命中 DENY 规则或默认拒绝 | `POLICY_DENIED` |

注意：签名值被改只报 `SIGNATURE_MISMATCH`；制品内容被改（签名仍合法）只报
`CONTENT_TAMPERED`，两者不会混为一谈。

## 3. 密钥与吊销语义

密钥记录包含 `validFrom`、`validUntil` 和可选的 `revokedAt`（吊销**生效时间**）。
密钥在任意时间点 `t` 的状态（`KeyStateEvaluator`）：

1. `t < validFrom` → `NOT_YET_VALID`
2. `revokedAt != null && revokedAt <= t` → `REVOKED`
3. `validUntil != null && t > validUntil` → `EXPIRED`
4. 其余 → `ACTIVE`

语义要点：

- **前瞻吊销**：吊销只影响 `revokedAt` 之后。吊销生效前合法签发、且判定时仍在
  `[notBefore, notAfter]` 内的证明不会被追溯判失效（响应里 `keyState=REVOKED` 仅作展示）。
- **吊销后禁止签发**：签发接口（`AttestationIssuer`）在 `issuedAt` 时刻检查密钥状态，
  非 `ACTIVE` 一律拒绝。
- **历史稳定复现**：准入请求可传 `evaluateAt` 指定判定时间；密钥状态、证明有效期、
  策略版本全部按该时间点计算。审计结论只写一次，后续新增吊销记录不会改写历史判定。
- 轮换 = 多把密钥并存，旧密钥到期/吊销后用新 `keyId` 签发，互不影响。

## 4. 策略与生效顺序

策略文件是带 `version` 与 `effectiveFrom` 的不可变文档。版本选择规则：
在 `evaluateAt` 时刻，选取所有 `effectiveFrom <= evaluateAt` 的策略中 **effectiveFrom 最新**
的版本。因此策略变更天然可追溯——同一份制品在不同历史时间点自动落到当时生效的版本。

规则按文件中的顺序自上而下评估，**首条全部约束满足的规则命中即生效**；
没有任何规则命中时使用 `defaultEffect`（演示策略为 `DENY`，默认拒绝）。
响应返回 `policyVersion`、`matchedRule` 和 `policyExplanation`，明确说明命中来源。

支持的约束（`PolicyDocument.Constraint`）：

- `issuerEquals`：签发者等于
- `keyIdIn`：keyId 属于白名单
- `artifactTypeEquals`：制品 `type` 字段等于
- `maxArtifactSize`：规范化后字节数上限
- `requireSigned`：必须已通过签名校验（策略阶段前置条件已保证）

新增策略只需放入新的 `policy-v{n}.json`，不要修改旧文件。

## 5. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/gate/admissions` | 提交准入请求 |
| `GET /api/gate/admissions/{requestId}` | 读取首次审计结论（幂等查询） |
| `POST /api/gate/attestations` | 本地签发证明（模拟可信签发端） |
| `POST /api/gate/keys/revoke` | 吊销密钥（可带生效时间） |

准入请求体：`{"requestId":"...","artifact":"<json 字符串>","attestation":"<json 字符串>",
"evaluateAt":1780272000000}`，`attestation` 与 `evaluateAt` 可空。

### 幂等与并发

- `requestId` 是幂等键：同一 requestId 重复提交返回首次结论（`cached=true`），
  且只产生一份审计文件。
- 同一 requestId 的在途请求按 key 加锁串行；审计文件采用临时文件 + 原子移动写入，
  并发下不会互相覆盖。
- 不同 requestId 的缓存、审计、摘要严格隔离（有 50 并发单测验证）。

## 6. 本地验证示例

```bash
# 签发
curl -s -X POST localhost:8080/api/gate/attestations \
  -H 'Content-Type: application/json' \
  -d '{"keyId":"key-team-a","issuer":"team-a-ci",
       "artifact":"{\"type\":\"release\",\"name\":\"app\",\"version\":\"1.0.0\"}"}'

# 准入（制品故意打乱字段顺序并加空白，结论仍一致）
curl -s -X POST localhost:8080/api/gate/admissions \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"demo-1",
       "artifact":" { \"version\":\"1.0.0\", \"name\":\"app\", \"type\":\"release\" } ",
       "attestation":"<上一步返回的 attestation 字符串>"}'

# 明天生效的吊销：今天仍可签发，吊销时刻后签发被拒
curl -s -X POST localhost:8080/api/gate/keys/revoke -H 'Content-Type: application/json' \
  -d '{"keyId":"key-team-a","revokedAt":<明天的 epoch millis>,"reason":"轮换下线"}'
```

## 7. 测试

`mvn test`，共 20 个用例，按业务分组，日志带 `[规范化]/[签名]/[吊销]/[轮换]/[策略]/
[幂等]/[并发]` 标签和每条用例的 PASS/结果明细：

- `CanonicalizationTest`：字段顺序/空白等价、篡改摘要变化、数字归一、非法 JSON
- `SignatureVerificationTest`：合法签名、篡改、签名损坏、缺失/不完整/未知密钥
- `KeyRevocationTest`：前瞻吊销、吊销后禁签、吊销边界、轮换与到期
- `PolicyDecisionTest`：v1/v2 历史复现、规则顺序、默认拒绝、尺寸约束
- `AdmissionIdempotencyConcurrencyTest`：重复提交幂等、50 并发同请求不覆盖、
  50 个异请求并发不串数据

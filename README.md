# 本地制品准入校验服务（Artifact Trust Gate）

一个完全在本地运行的制品签名 / 证明（attestation）校验与准入判定服务。
用本地 JSON 文件模拟制品、签名和密钥材料，**不依赖任何外部服务、KMS 或真实凭据**。

- 技术栈：Java 21+、Spring Boot 3.4、JUnit 5；密钥算法 RSA-2048 + SHA256withRSA。
- 数据目录：默认 `./data`（可用 `--trustgate.data-dir=...` 覆盖），所有状态为本地 JSON 文件。

## 1. 快速开始

```bash
mvn spring-boot:run                 # 首次启动自动生成演示密钥、证明、策略
mvn test                            # 运行 33 个单测，控制台直接打印业务覆盖与逐条结果
```

首次启动会在数据目录生成：

| 文件 | 含义 |
| --- | --- |
| `keys.json` | 密钥材料（公钥/私钥 PEM），仅追加，轮换不删除旧密钥 |
| `revocations.json` | 吊销账本，仅追加；条目数即密钥状态快照版本号 |
| `policies.json` | 策略版本，仅追加、不可修改 |
| `audit.json` | 准入审计记录，按自然键去重，仅追加 |
| `demo-artifact.json` / `demo-attestation.json` | 可直接提交的演示制品与证明 |

删除数据目录（或更换 `--trustgate.data-dir`）即可回到全新初始状态。

## 2. 校验协议

### 2.1 制品规范化与指纹

制品内容是一段 JSON。校验前先做 **JCS 风格规范化**（`JsonCanonicalizer`）：

- 对象成员按键名 UTF-16 字典序排列，数组顺序保持不变；
- 去除所有缩进、换行、多余空白；统一字符串转义与数字表示。

制品指纹 = `SHA-256(规范化字节)`。因此同一份内容在**字段顺序、空白差异**下指纹完全一致，
判定结论一致；而任何值改动、数组顺序变化都会改变指纹。

### 2.2 证明（Attestation）与签名

证明字段：`attestationId`、`subjectDigest`（制品指纹）、`keyId`、`issuedAt`、`expiresAt`、`signature`。

- 签名载荷 = 上述前 5 个字段的**规范化 JSON**（与制品同一套规范化规则）；
- 签名算法 `SHA256withRSA`，`signature` 为 Base64；
- 验签使用 `keys.json` 中登记的公钥（PEM）。

### 2.3 校验顺序与拒绝原因（严格区分，不做笼统失败）

提交校验按以下顺序短路，每类失败有独立 `DecisionCode`：

| 顺序 | 条件 | code |
| --- | --- | --- |
| 1 | 缺少制品 / 制品不是合法 JSON | `REJECT_UNKNOWN_ARTIFACT` |
| 2 | 缺少证明对象 | `REJECT_ATTESTATION_MISSING` |
| 3 | 证明缺少 `signature`（材料不完整） | `REJECT_SIGNATURE_MISSING` |
| 4 | `keyId` 未登记（含轮换下线后不可作为新信任源） | `REJECT_KEY_UNKNOWN` |
| 5 | 制品指纹 ≠ 证明的 `subjectDigest`（**内容被篡改**） | `REJECT_CONTENT_DIGEST_MISMATCH` |
| 6 | 签名与载荷/公钥不匹配（证明被改、签名伪造、乱码） | `REJECT_SIGNATURE_INVALID` |
| 7 | `issuedAt` 晚于评估时间（未来签发） | `REJECT_ATTESTATION_EXPIRED` |
| 8 | 评估时间 ≥ `expiresAt`（已过期；到期时刻即失效，早 1 秒有效） | `REJECT_ATTESTATION_EXPIRED` |
| 9 | 密钥吊销在签发时刻已生效 | `REJECT_KEY_REVOKED` |
| 10 | 策略拒绝 / 版本不存在 | `REJECT_POLICY_DENY` / `REJECT_POLICY_VERSION_UNKNOWN` |

注意顺序语义：**先确认内容没被篡改（5），再确认签名本身合法（6），最后才看吊销（9）**。

## 3. 密钥与吊销语义

### 3.1 轮换

- `POST /api/admin/keys/rotate?oldKeyId=key-a&newKeyId=key-a2`：登记新密钥，
  旧密钥标记 `replacedBy`，但**旧密钥材料保留**，历史制品仍可用旧公钥验签。

### 3.2 吊销（带生效时间，仅追加）

- `POST /api/admin/keys/{keyId}/revoke`，请求体 `{"effectiveAt": "...", "reason": "..."}`；
- `effectiveAt` 是**吊销生效时间**，允许未来时间（定时吊销）；
- **拒绝倒填**：`effectiveAt` 早于登记时间（容忍 1 秒时钟偏差）直接 `REJECT_BAD_REQUEST`，
  从制度上保证“后来的登记不能改写已经发生的历史”；
- 吊销记录只追加，不可删除。

判定语义（关键）：

- **生效前签发**、且在评估时刻仍处于 `[issuedAt, expiresAt)` 有效期内的证明：**继续有效**
  （吊销不追溯，给已发布制品宽限）；
- **生效后签发**的证明：一律 `REJECT_KEY_REVOKED`；
- 吊销生效后，签发接口拒绝再用该密钥签发（`issue` 会检查生效状态）。

### 3.3 历史复现：密钥状态快照

`revocations.json` 的**条目数即为快照版本号**：快照 vN = 账本前 N 条记录，天然不可变。

- 请求可固定 `keyBookVersion`：`0` 表示无任何吊销的初始快照；
- 后来新增的吊销记录只会产生新版本，**不会改写旧快照下的历史结论**；
- 不传则使用最新快照，返回中带 `keyBookVersion`，审计中持久化该版本。

## 4. 准入策略与生效顺序

- 策略以**版本**为单位发布：`POST /api/admin/policies`，版本号自增、内容不可变；
- 每个版本是一组规则 `{ruleId, matchKeyId, allow, message}`；
- **按声明顺序 first-match-wins**：第一条 `matchKeyId` 等于签名密钥的规则命中；
  `matchKeyId` 为空串/null 表示**默认规则**；
- 没有规则命中（也没有默认规则）时 **fail-closed 默认拒绝**；
- 结论中返回 `matchedRuleId` 说明命中了哪条规则。

请求可固定 `policyVersion` 复现历史版本判定；不传则使用最新版本。
于是“同一制品在不同策略版本下的判定”各自独立、可复现、可审计。

## 5. 审计、幂等与并发

- 判定自然键 = `制品规范化指纹 | 证明全字段指纹(含signature) | 评估时间标记 | 策略版本 | 密钥快照版本`；
- 未显式传 `evaluationTime` 时使用固定符号 `LATEST`：同一策略/快照版本内重复提交
  返回**同一结论、同一 submissionId**，`reusedAuditRecord=true`，且**只产生一条审计**；
- 评估时间不同、证明材料不同（含缺签名）、策略或密钥快照版本不同，都会形成新的独立判定；
- 并发：按自然键哈希做 16 段分段锁，同键串行（双检后写入）、异键并行；
  审计文件原子写入。因此并发重复提交不会互相覆盖，不同制品不会串数据。

## 6. HTTP 接口

### 准入

```
POST /api/admission/submit     # 提交校验
GET  /api/admission/audit      # 查询审计记录
```

提交请求体：

```json
{
  "artifact": { "contentJson": "{\"name\":\"svc\",\"version\":\"1.0\"}" },
  "attestation": {
    "attestationId": "att-...",
    "subjectDigest": "sha256-hex",
    "keyId": "key-a",
    "issuedAt": "2026-01-10T08:00:00Z",
    "expiresAt": "2026-02-10T08:00:00Z",
    "signature": "base64..."
  },
  "evaluationTime": "2026-01-11T00:00:00Z",
  "policyVersion": 1,
  "keyBookVersion": 0
}
```

后三个字段均可选：不传 `evaluationTime` 表示按当前时间；版本号不传表示用最新。

### 管理

```
POST /api/admin/attestations/issue            # 本地演示签发 {keyId, contentJson, ttlSeconds}
POST /api/admin/keys?keyId=key-a              # 登记新密钥（本地生成 RSA 对）
POST /api/admin/keys/rotate?oldKeyId=&newKeyId=
POST /api/admin/keys/{keyId}/revoke           # {effectiveAt, reason}
POST /api/admin/policies                      # 发布新策略版本（规则数组）
GET  /api/admin/keys | /revocations | /policies | /keybook/latest
```

### 一次本地验证（启动后）

```bash
# 用种子数据提交（应 ALLOW，命中 allow-key-a）
curl -s -X POST localhost:8080/api/admission/submit \
  -H 'Content-Type: application/json' \
  --data @data/demo-attestation.json

# 查看审计；重复上面的提交，审计条数不变， reusedAuditRecord=true
curl -s localhost:8080/api/admission/audit

# 发布只允许 key-b 的新版本策略后，同一证明在最新版本被拒、固定 policyVersion=1 仍放行
curl -s -X POST localhost:8080/api/admin/policies -H 'Content-Type: application/json' \
  -d '[{"ruleId":"default-deny","matchKeyId":null,"allow":false,"message":"v2 全拒"}]'
```

## 7. 测试

`mvn test` 共 33 个用例，分四个业务块（用例名即业务点，日志逐条打印
`▶ 开始用例 / ✔ 通过 / ✖ 失败`，Surefire 已配置 `useFile=false` 直接输出到控制台）：

- `CanonicalizationAndDigestTest`：字段顺序/空白等价、篡改/数组顺序差异；
- `SignatureVerificationTest`：合法验签、内容篡改、证明载荷被改、错密钥签名、
  乱码签名、缺签名、缺证明、未知密钥、过期与到期边界；
- `KeyRotationRevocationTest`：轮换保留旧密钥、定时吊销未生效、生效后禁止签发、
  生效前签发的证明宽限有效、快照历史复现、拒绝倒填、未知密钥；
- `PolicyAndAdmissionTest`：first-match 顺序、多版本复现与命中规则、
  拒绝原因区分、幂等/审计去重（含“缺签名不串结论”回归）、32 并发同键只留 1 条审计、
  20 个不同制品并发不串数据、历史评估时间回放。

## 8. 目录结构

```
src/main/java/.../
  crypto/     JsonCanonicalizer、Digests(SHA-256)、RsaSignatureService
  model/      领域模型与细分 DecisionCode
  store/      本地 JSON 仓库（keys/revocations/policies/audit，原子写入）
  service/    Attestation/Verification/Policy/Admin/Admission 服务
  web/        REST 控制器与异常处理
  bootstrap/  首次启动演示数据
src/test/.../tests/
  support/    可控时钟 TestClock、业务日志扩展、临时目录手工装配的 LocalHarness
```

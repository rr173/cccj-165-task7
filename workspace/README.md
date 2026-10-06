# pwncorpus — 泄露口令指纹语料的匿名查询发布系统

k-匿名（HIBP 风格）的口令泄露查询服务。纯 Python 标准库实现（Python ≥ 3.10，零第三方依赖），SQLite 存储。

## 安全模型与核心不变量

| 要求 | 实现 |
|---|---|
| 永不暴露单条原始口令 | 摄取端入库即 SHA-1 哈希，原始口令只存在于请求作用域，不落盘、不日志、不出现在任何响应；支持客户端预哈希（`{"sha1": "..."}`）使原始口令不离开客户端；测试验证数据库文件与全部 API 面均不含原始口令 |
| 来源批次去重 | 幂等键 + `(source, content_sha256)` 唯一约束；重复批次返回原 `batch_id`，不重复计数；并发提交同批次由 `BEGIN IMMEDIATE` 串行化，有且只有一个"非重复" |
| 授权验证 | 作用域令牌（`ingest` / `retract` / `publish`），库中只存令牌哈希 |
| 固定前缀分桶 | 系统级固定 `PREFIX_LEN = 5`（SHA-1 十六进制前 5 位），每个版本记录 `prefix_len` 供验证器核对 |
| 最小集合规模 | 构建发布时，后缀数 < `threshold_k` 的桶被**整体丢弃**，不出现在版本、导出和查询中；`k` 是版本属性而非全局可变配置 |
| 撤回/修正只产生新版本 | `retract` / `corrections` 只打标记，在**下一次 build + activate** 才生效；当前服务版本不受影哃；发布版本不可变 |
| 草稿不覆盖新来源状态 | 候选版本记录构建时的语料状态标记（`corpus_state`）；批次新增/撤回/纠错在同一写事务内推进该标记；激活时比对，不一致则拒绝（409），现行版本与查询不受影响；冲突后可**刷新草稿**（保留版本号与 k）再继续预览与启用 |
| 旧版本可验证但不可查 | 版本状态机 `candidate → active → retired`；查询只读 `active`；`retired` 版本的清单与桶数据永久保留，可随时导出并用离线验证器校验 |
| 查询不混版 | 激活是单事务原子切换（旧版本退役 + 候选激活 + 指针交换）；查询在单个 SQLite 快照内读取版本指针和桶数据，响应携带 `X-Corpus-Version` 供客户端核对 |

## 架构

```
                ┌──────────── 摄取端（需授权）────────────┐
  批次提交 ───▶ │ 去重(内容哈希/幂等键) → 入库即哈希 → 批次表 │
                └───────────────┬────────────────────────┘
                                ▼
                    活跃语料 = Σ活跃批次 − 撤回 − 修正
                                ▼  build（候选版本，不可变）
                固定前缀分桶 → 丢弃 |桶| < k 的桶 → 清单哈希
                                ▼  审查页 diff（陈旧草稿先刷新）→ activate（比对状态标记 + 单事务原子切换）
                ┌──────────── 发布端（匿名）──────────────┐
  GET /range ─▶ │ 仅服务 active 版本：后缀摘要 + 出现次数     │
                └─────────────────────────────────────────┘
  任意版本 ─▶ export → 离线验证器（清单哈希/格式/阈值/排序全量校验）
```

## 快速开始

```bash
export PYTHONPATH=/workspace

# 初始化 + 发令牌（令牌只显示一次）
python3 -m pwncorpus.cli --db corpus.db init
python3 -m pwncorpus.cli --db corpus.db token --label ingestor --scopes ingest
python3 -m pwncorpus.cli --db corpus.db token --label publisher --scopes publish,retract

# 摄取（文件中每行一个口令，或 sha1:<hex> 预哈希）
python3 -m pwncorpus.cli --db corpus.db ingest --source breach-2026Q3 --file leak.txt

# 构建候选版本（k = 最小集合规模）→ 审查 → 激活
python3 -m pwncorpus.cli --db corpus.db build --k 50
python3 -m pwncorpus.cli --db corpus.db activate --version 1

# 启动服务
python3 -m pwncorpus.cli --db corpus.db serve --host 127.0.0.1 --port 8080
```

## API

### 匿名查询（无需令牌）

```
GET /api/range/{5位十六进制前缀}
→ 200 text/plain:  "SUFFIX:COUNT\n..."   +  X-Corpus-Version: N
→ 404 桶不存在 / 被阈值抑制      503 无活跃版本      400 前缀非法
```

客户端只发送哈希前缀（k-匿名），服务器永远看不到完整口令或完整哈希。

### 批次 API（Bearer 令牌）

| 端点 | 作用域 | 说明 |
|---|---|---|
| `POST /api/batches` | `ingest` | `{"source", "items": [...], "idempotency_key"?}`；items 为原始口令或 `{"sha1":"..."}`；重复批次返回 `200 {"duplicate": true}` |
| `POST /api/batches/{id}/retract` | `retract` | 撤回批次，下一发布版本生效 |
| `POST /api/batches/{id}/corrections` | `retract` | `{"items": [...]}` 误报修正，剔除指定指纹，下一发布版本生效 |
| `POST /api/publications/build` | `publish` | `{"k": 50}` 构建候选版本 |
| `POST /api/publications/{v}/activate` | `publish` | 原子切换；草稿陈旧或确认绑定（可选 `expected_manifest`）不匹配时 409，现行版本不变 |
| `POST /api/publications/{v}/refresh` | `publish` | 用当前来源数据原地重建候选（保留版本号与 k），解除陈旧冲突 |
| `GET /api/publications` `/…/{v}` | `publish` | 版本列表 / 详情 + 与活跃版本的 diff |
| `GET /api/publications/{v}/manifest` | 公开 | 任意版本清单（仅哈希），支撑独立验证 |
| `GET /review` | `publish` | 发布审查页（`?token=` 或 Bearer） |
| `GET /api/health` | 公开 | 健康检查 + 当前版本 |

### 发布审查页

`GET /review?token=<publish令牌>` 展示：活跃版本与候选版本元数据（k、桶数、清单哈希、语料状态标记）、候选与活跃版本的 diff（桶增删、后缀增删、计数变化及抽样）、近期批次、历史版本，以及需要重新输入 publish 令牌的激活按钮。

草稿生成后来源数据可能继续变化。审查页会标明候选草稿是否仍对应当前来源数据：陈旧（STALE）时激活按钮被刷新表单取代——刷新用当前数据原地重建草稿（保留版本号与阈值 k），随后照常预览与启用；未变化时审批流程不变。激活表单通过隐藏字段绑定所审草稿的清单哈希，确认时草稿若已被替换（如他人刷新过）会被拒绝并提示重新加载。

### 离线分桶验证器

```bash
python3 -m pwncorpus.cli --db corpus.db export --version 1 --out export-v1

python3 -m pwncorpus.verifier verify export-v1          # 全量校验导出
python3 -m pwncorpus.verifier check-response export-v1 ABCDE resp.txt  # 在线响应核对发布物
python3 -m pwncorpus.verifier lookup export-v1          # 完全离线的口令查询（不联网）
```

`verify` 校验：清单自哈希、每个桶文件 SHA-256 与清单一致、行格式（后缀长度/计数 ≥ 1）、桶内排序去重、**每个桶满足最小集合规模 k**、无多余/缺失文件。任何篡改（改计数、加小桶、换文件）都会失败。

### 离线增量包（两个发布版本之间）

离线镜像无需为每次发布重新下载完整发布物。增量包只携带发生变化的桶，并明确绑定起始与目标两个版本：

```bash
# 在发布端（有 corpus.db）：直接从两个已发布版本生成
python3 -m pwncorpus.cli --db corpus.db delta-generate \
    --from-version 1 --to-version 2 --out delta-v1-v2

# 或者完全离线：对两份全量导出目录生成（发布端只传增量包即可）
python3 -m pwncorpus.delta build export-v1 export-v2 delta-v1-v2
```

包结构（纯标准库，目录形式）：

```
delta-v1-v2/
  delta.json                 # 绑定信息 + 起始/目标的【完整清单】 + 分桶清单 + 自哈希
  payloads/added/<前缀>.txt   # 目标版本新增的桶（完整桶文件）
  payloads/modified/<前缀>.txt # 两版本都存在但内容不同的桶（目标版完整桶文件）
  # 删除桶不携带内容：delta.json 记录前缀和起始版桶的 SHA-256，应用时先核对再删除
```

`delta.json` 内含：`format`、`from_version`/`to_version`、`from_manifest_sha256`/`to_manifest_sha256` 绑定、**两份完整嵌入清单**（各自带 `manifest_sha256`）、`added` / `modified` / `deleted` / `unchanged` 四个互斥分桶、每个载荷的 SHA-256（同时等于目标清单中该桶的哈希），以及对上述全部内容做规范 JSON 哈希得到的 `delta_sha256`。

```bash
# 检查增量包自身完整性（可附带本地基线核对绑定）
python3 -m pwncorpus.delta check delta-v1-v2
python3 -m pwncorpus.delta check delta-v1-v2 --baseline mirror

# 应用到本地镜像（原子化、可恢复）
python3 -m pwncorpus.delta apply delta-v1-v2 mirror
# 上次应用被中断时：继续执行会向前恢复到目标版本；也可回滚回起始版本
python3 -m pwncorpus.delta apply delta-v1-v2 mirror            # 恢复（向前完成）
python3 -m pwncorpus.delta apply delta-v1-v2 mirror --rollback # 回滚到 v1
```

安全性质：

- **应用前双侧核对**：增量包必须自哈希一致、嵌入清单自洽、分桶与两份嵌入清单严格可推导、载荷哈希与文件内容和目标清单三方一致、无缺失/多余载荷；本地镜像必须通过原全量验证器，且其清单哈希与包绑定的起始版本完全一致（基线不匹配直接拒绝）。
- **应用后与全量导出逐字节相同**：应用结果用原 `verifier verify` 全量校验通过，且与目标版本的全量导出目录逐文件、逐字节一致（写入的目标 `manifest.json` 与 `export` 输出格式完全相同）。
- **原子化与中断恢复**：所有检查在触碰镜像前完成；切换阶段用 `.delta-apply.json` 日志 + `.delta-stage/`（新增/修改桶暂存区 + 被替换/删除桶备份 + 起始清单备份）记录。删除与替换均可重复执行：写入中断后再次 `apply` 向前恢复到目标版本，`--rollback` 无条件恢复到精确的起始版本（不信任日志状态位，任何中断点都可恢复）。暂存完成而日志尚未登记即掉电时，镜像尚未被触碰：再次 `apply` 丢弃孤立暂存区后重新暂存并完成同一切换；`--rollback` 清除孤立暂存区并如实报告"无可回滚"（镜像从未离开起始版本），不会误报已回滚。恢复的任一种终态都通过原验证器。
- **错误清晰、镜像不被半升级**：基线不匹配、包被篡改、内容缺失、写入中断均返回明确错误（非零退出码 + `FAIL:` 信息）；切换前失败时镜像原样不动且仍通过原验证器；中断后必须用同一增量包恢复，混入其他增量包会被明确拒绝。
- **重复应用幂等**：镜像已是该增量的目标版本时，应用是经核验的空操作，不会破坏任何内容；镜像若已被篡改，则验证失败而不会被"顺手修复"掩盖。
- 全量导出、在线查询与旧版本验证行为完全不变（验证器逻辑被重构为可复用的函数，校验项与输出保持一致）。

## 并发设计

- SQLite WAL + 每请求独立连接；写事务 `BEGIN IMMEDIATE`（带忙等待与重试），读事务为快照隔离。
- 并发摄取同批次：唯一约束保证只入库一次，其余线程拿到已有 `batch_id`。
- 构建候选版本读取单语句快照，与并发摄取互不阻塞；候选版本不可变。
- 激活为单事务：旧版本退役、候选激活、指针交换同时提交；进行中的查询要么看到旧版本完整数据、要么看到新版本完整数据，绝不混版（有并发测试覆盖）。
- 激活是与来源写入的 compare-and-swap：候选记录构建时的 `corpus_state` 标记，激活在写事务内复比。**来源更新先提交**则本次确认 409 不生效、现行查询保持不变；**激活先提交**则后来的来源更新只进入下一版。构建/刷新在同一快照中读取语料与状态标记，提交前复核，保证记录的标记与数据严格对应。
- 无实际效果的来源写入（重复批次、重复撤回、重复纠错）不推进状态标记，不会误判草稿为陈旧。
- 阈值 k 是版本属性：调整 k 必须构建新版本，旧版本按其自身 k 继续可验证。

## 部署注意事项

- 开发服务器不终止 TLS；生产环境置于反向代理之后并强制 HTTPS，防止前缀查询被窃听。
- 审查页支持 `?token=` 传参（便于浏览器），令牌会出现在 URL 中——生产环境建议改用反向代理注入 `Authorization` 头或加 SSO 前置；访问日志已对 `token=` 做脱敏。
- 建议客户端优先使用 `{"sha1": "..."}` 预哈希提交，原始口令不跨网络。
- 未实现响应填充（padding）与速率限制；高敏部署可在代理层加 padding 与限流以抵抗流量分析。

## 可重放来源责任账本（provenance ledger）

在摄取流水线之外，另有一个**追加式、签名链化**的来源责任账本，跨越三个独立边界工作：命令行写入、持久化 SQLite、独立审计/离线核验进程。它不改变上面的任何摄取、发布、全量导出与增量升级命令。

### 信任模型与数据结构

- **链项（entry）**：`register / submit / retract / correct` 四类。每项含无间隙 `seq`、来源名、规范化 payload、时间戳、幂等 `claim_id`、来源签名所用公钥、签名与 `prev_hash`；`entry_hash` 对除自身外的全部字段做规范 JSON 哈希，`prev_hash` 指向前一项，第一项指向 `GENESIS:<ledger_id>`。
- **来源密钥**：来源持 Ed25519 密钥（纯标准库 `pwncorpus/ed25519.py`，RFC 8032）。`register` 把来源名绑定到公钥（自签名）；之后每条声明都用该私钥签名，写入事务内逐条验签，伪造声明永不上链。账本另持有一把 **genesis 密钥**（私钥文件 0600，不入库），用于为快照签名。
- **责任语义**：`submit` 携带输入文件 SHA-256 与该批贡献的分桶前缀集合（只存哈希/前缀，不存桶内容）；`retract` 以**链序号 + 文件摘要**绑定某次提交并附**必填撤回理由**；`correct` 记录被纠错的指纹。只有提交者本人可撤回/纠错其提交（否则来源权限错误）。撤回与纠错的先后即链上先后，快照明确给出"纠错是否发生在撤回之前"。

### 三个边界

```bash
export PYTHONPATH=/workspace
# 边界 1：写入（命令行 -> 追加式 SQLite 签名链）
python3 -m pwncorpus.cli --db corpus.db ledger-init --key genesis.key
python3 -m pwncorpus.cli --db corpus.db ledger-keygen --source breach-co --key src.key
python3 -m pwncorpus.cli --db corpus.db ledger-register --source breach-co --key src.key
python3 -m pwncorpus.cli --db corpus.db ledger-submit   --source breach-co --key src.key --file leak.txt
python3 -m pwncorpus.cli --db corpus.db ledger-correct  --source breach-co --key src.key --claim-seq 2 --file falsepos.txt
python3 -m pwncorpus.cli --db corpus.db ledger-retract  --source breach-co --key src.key --claim-seq 2 --file leak.txt --reason "court order"
python3 -m pwncorpus.cli --db corpus.db ledger-head

# 边界 2：独立审计进程（只读数据库，整链校验后导出带 TTL 的签名时间点快照）
python3 -m pwncorpus.audit verify --db corpus.db
python3 -m pwncorpus.audit export --db corpus.db --key genesis.key --out snap.json --ttl 86400
python3 -m pwncorpus.audit export --db corpus.db --key genesis.key --out old.json --as-of 2026-09-01T00:00:00+00:00

# 边界 3：无数据库连接的离线核验（仅凭快照 + 输入摘要/指纹）
python3 -m pwncorpus.attest verify snap.json
python3 -m pwncorpus.attest check  snap.json --fingerprint <40-hex-sha1> --source breach-co
python3 -m pwncorpus.attest check  snap.json --fingerprint <40-hex> --source breach-co --file leak.txt
python3 -m pwncorpus.attest check  snap.json --prefix ABCDE
```

`attest` 模块**不导入 sqlite3**；把 `corpus.db` 移走后核验照常工作。

### 快照与核验

快照绑定 `ledger_id / genesis_pub / head_seq / head_hash / created_at / not_after / ttl / prefix_len / 全部链项 / 由链重放得到的责任记录`，整体自哈希后由 genesis 密钥签名。离线侧依次校验：结构 → 自哈希 → genesis 签名 → 是否过期 → 全链重放（序号无间隙、`prev_hash` 相连、每条来源签名、责任语义）→ 重放结果与嵌入记录逐字节一致。

核验回答：某条分桶记录**是否曾由指定来源提交、提交时间、何时被撤回及理由、撤回前后是否发生过纠错**。

### 明确的失败结果

| 情形 | 结果 |
|---|---|
| 快照超过 `not_after` | `FAIL: snapshot is EXPIRED`，须取新快照 |
| 删除/重排链项 | 链序号或 `prev_hash` 断裂，整链校验失败 |
| 篡改链项或责任记录 | 重放哈希/自哈希不一致 |
| 伪造来源签名 | 写入时与离线重放均拒绝 |
| 输入摘要与提交不符 | `digest mismatch` |
| 指定来源未注册 / 非本人撤回纠错 | `source permission` |
| 并行写入冲突 | 链顶条件更新（CAS）失败方回滚重试；`--expect-head` 过期则明确冲突 |
| 旧快照覆盖较新状态 | 导出拒绝（现有快照 head_seq 更新时），同 head 续期 TTL 允许 |

失败信息**不含**被查询的指纹、前缀或摘要（有测试断言）。

### 幂等、可重放与并发

- **重复提交返回原记录**：相同 `claim_id`，或相同 `来源+文件摘要`（撤回/纠错同理用语义键），返回原链项且 `duplicate:true`，不追加、不重复计数；跨进程、中断后重跑同样成立。
- **从最后链项继续**：`ledger-replay --intents claims.jsonl` 批量追加；已在链上的声明跳过为 duplicate，崩溃后用同一文件重放即从断点继续。
- **并行写入不分叉**：写事务 `BEGIN IMMEDIATE` 串行化，并以单行 `ledger_head` 的**条件更新**（`WHERE head_seq/head_hash = 所观察的前驱`）做原子 compare-and-set。SQLite WAL 下排队等待写锁的连接可能持有等待前的读快照（即使已拿到写锁）；CAS 影响 0 行即暴露陈旧快照，回滚重试，哈希链因此永不分叉。

## 按调用方隔离的每日隐私预算（privacy budget）

在匿名 `/api/range` 查询之外，另有一套**按调用方（tenant）隔离、按 UTC 日滚动**的隐私预算，跨越四个边界工作：HTTP 服务、持久化 SQLite、管理入口与一个**断网隔离审计程序**。未运行 `budget-init` 时 `/api/range` 完全保持原有匿名行为；初始化后每次前缀读取都必须携带查询令牌并消耗一次额度。

### 六字段预算桶

预算桶表**只有六个字段**（其余信息全部在独立的表中）：

| 字段 | 含义 |
|---|---|
| `tenant_id` | 调用方编号（与被查询内容无关） |
| `window_start` | UTC 日历日 00:00 的 unix 秒 |
| `remaining` | 当日剩余额度，`CHECK(remaining >= 0)` 永不为负 |
| `spent` | 当日已扣减次数 |
| `frozen` | 该（调用方, 窗口）是否冻结 |
| `policy_revision` | 播种该桶时生效的不可变策略版本号 |

- **扣减与正文读取同一原子事务**：`BEGIN IMMEDIATE` 内完成鉴权 → 幂等 → 选最严租户 → 条件扣减（`UPDATE ... SET remaining=remaining-1 WHERE remaining>0 AND frozen=0`）→ 同事务读版本指针与桶行 → 写事件 → 提交。不存在"扣了没给/给了没扣"；提交前崩溃整体回滚，无负数余额、无重复扣减、无半条冻结记录。
- **并行不双扣、不绕限**：写锁串行化 + 条件 UPDATE 影响行数校验；高倍并发下恰好只成功 `quota` 次。
- **读不存在的桶也扣一次**（真实读取，记为 `not_found`）；但**无活跃版本（503）不扣费**。
- **冻结**：单事务翻转租户标志与当前窗口桶标志并写管理日志；冻结期间任何请求都拿不到正文也不扣费，解冻后恢复；冻结跟随租户进入新 UTC 窗口，过去窗口标志永不改写。
- **两枚令牌按更严者处理**：`Authorization: Bearer <t1>, <t2>`；冻结 > 已耗尽 > 剩余更少，只对最严租户扣一次。
- **撤销与消费先到先得**：共用写锁，顺序即提交顺序；已识别但撤销的令牌明确返回 `token_revoked`(403)，完全陌生的令牌是 401（不建立任何调用方状态）。
- **UTC 日历窗口**：一律按 UTC 午夜滚动，与宿主机时区无关；跨日得到按当时策略播种的新桶。
- **策略变化不改写历史**：新默认额度只追加一行不可变策略版本，仅影响之后的窗口；旧审计材料的每个窗口绑定其原始版本号，新策略无法覆盖旧余额复算。

### 管理入口（需 `budget-admin` 作用域）

```bash
export PYTHONPATH=/workspace
python3 -m pwncorpus.cli --db corpus.db budget-init --key budget.key --daily-quota 100
python3 -m pwncorpus.cli --db corpus.db token --label budgetops --scopes budget-admin
python3 -m pwncorpus.cli --db corpus.db budget-token    --tenant svc-7 --label ci
python3 -m pwncorpus.cli --db corpus.db budget-topup    --tenant svc-7 --amount 50 --note "surge"
python3 -m pwncorpus.cli --db corpus.db budget-freeze   --tenant svc-7
python3 -m pwncorpus.cli --db corpus.db budget-unfreeze --tenant svc-7
python3 -m pwncorpus.cli --db corpus.db budget-revoke   --token-id btid_xxxxxxxx
python3 -m pwncorpus.cli --db corpus.db budget-policy   --daily-quota 200  # 只影响之后的新窗口
python3 -m pwncorpus.cli --db corpus.db budget-status   [--tenant svc-7] [--window 2026-10-06]
```

HTTP 管理端点：`POST /api/budget/tenants/tokens`、`/api/budget/tenants/{t}/topup|freeze|unfreeze`、`POST /api/budget/tokens/{id}/revoke`、`GET /api/budget/status` 与 `/api/budget/tenants/{t}/status`。**管理端计数与审计导出共用同一聚合函数，逐项相加必然一致。**

### 查询响应隔离语义

```
GET /api/range/{prefix}   Authorization: Bearer <查询令牌>[, <第二枚>]
200 正文（X-Budget-Tenant / -Remaining / -Policy-Revision / X-Corpus-Version）
404 桶不存在（仍扣一次）   429 budget_exhausted（带 Retry-After）
403 frozen / token_revoked   401 未识别令牌（不泄露桶信息）   503 无活跃版本（不扣费）
```

耗尽/冻结响应**不区分桶是否存在**（存在与不存在的前缀返回相同状态/错误码/响应体），响应头只回调用方自己的编号与余额，绝不携带其他调用方或被查内容的状态。`Idempotency-Key` 支持重复请求返回原始结果且只扣一次（并行同键也只一次），键与租户绑定。

### 三个边界：导出 → 断网校验

```bash
# 独立审计进程（只读打开 DB；先做桶表 vs 事件/追加流水的内部一致性交叉校验）
python3 -m pwncorpus.budgetaudit verify --db corpus.db
python3 -m pwncorpus.budgetaudit export --db corpus.db --key budget.key \
    --out budget-export.json [--as-of 2026-10-01T00:00:00+00:00] \
    [--previous prev.json] [--overwrite]

# 断网侧（budgetverify 不导入 sqlite3；移走 corpus.db 照常工作）
python3 -m pwncorpus.budgetverify verify budget-export.json
python3 -m pwncorpus.budgetverify daily budget-export.json --tenant svc-7 --date 2026-10-06
python3 -m pwncorpus.budgetverify check  budget-export.json --tenant svc-7 --date 2026-10-06 --nth 150
```

导出物是单个 Ed25519 签名 JSON，**只含**调用方编号、UTC 窗口、策略版本、扣减次数、失败原因计数（`budget_exhausted/frozen/token_revoked`）与追加额度；字段白名单严格校验，多余字段（如偷塞前缀）即失败。校验顺序：结构/白名单 → 自哈希 → genesis 签名 → 策略版本自 1 无间隙 → 逐窗口算术且非负。脱离服务即可复算：

```
remaining = policy[revision].daily_quota + Σgrants.amount − deductions
```

`check --nth N`：`within_budget`（容量内且已记录）/ `within_budget_unrecorded`（容量内但无此扣减）/ `over_budget` / `no_record`。

- **篡改即失败**：改数字 → 自哈希不符；重哈希但无 genesis 私钥 → 签名不符；伪造整窗使扣减 > 配额+追加 → 余额为负被拒；旧窗口挂到不存在的新版本号 → 被拒；钉扎公钥不符 → 被拒。
- **库外篡改在导出时被拦**：直接改库使桶表与事件流不一致（如 `spent` 多 1），审计明确报 `disagrees`，绝不粉饰。
- **旧材料不可被覆盖**：默认拒绝用不同材料覆盖同一路径；`--previous` 要求前一份可验真且事件序号不更新；旧时点导出不能挂在更新导出之后。
- 事件表追加式，只记 `tenant/window/result/timestamp`，不含前缀、后缀、指纹或原始口令（测试对导出文件做敏感子串断言）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

146 个用例：原有 87 个（摄取/发布/导出/增量 + 责任账本，行为不变），新增 59 个隐私预算用例——首次请求建桶与事务前后余额、不存在桶 404 仍扣费、无活跃版本不扣费、幂等键重复/并行同键/跨租户绑定、高并发恰好用尽不双扣、多租户独立、两令牌更严者（冻结/耗尽/剩余）治理、耗尽响应不区分桶存在、原始 SQL 也无法做成负余额、追加提额、冻结/解冻与跨日跟随、冻结/扣减提交前崩溃回滚（无半条冻结、无重复扣减）、撤销幂等与撤销-消费多轮 FCFS、UTC（非本机时区）窗口与跨日恢复、策略新版本不改旧窗口、重启后余额恢复（含真实子进程重新发起查询而非探活）、管理计数与导出逐项一致、导出物字段白名单与敏感子串断言、移走 DB 后断网复算余额/判定第 N 次请求、伪造窗口/篡改数字/重哈希伪造签名/钉扎公钥不符/多余字段/版本号改写拒绝、导出链接与旧材料保护、`--as-of` 时点导出、库外篡改被审计拒绝，以及四边界经真实子进程（CLI 管理 → 独立 `budgetaudit` 只读导出 → 无数据库 `budgetverify` 校验）。



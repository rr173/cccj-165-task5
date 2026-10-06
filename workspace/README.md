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

## 来源责任账本（可重放、可离线裁决）

为离线语料仓库提供与主库**完全独立**的追加式来源责任账本（独立 SQLite 文件 + 独立 HMAC 密钥），跨越三个边界：命令行提交 → 追加式持久化哈希链 → 独立审计进程导出时间点快照 → **无数据库连接**的离线工具只凭快照和一条输入摘要作出裁决。现有摄取、发布、全量导出、增量升级命令均不改变。

```bash
# 初始化账本（生成 ledger.db 与 0600 的 ledger.db.key；密钥带外分发给审计方）
python3 -m pwncorpus.cli --ledger ledger.db ledger-init

# 注册来源，得到一次性提交令牌（库中只存令牌哈希）
python3 -m pwncorpus.cli --ledger ledger.db ledger-source --source breach-2026Q3

# 提交来源声明：文件每行一个 40 位 SHA-1 指纹（或 sha256rec:<hex64> 预摘要）
python3 -m pwncorpus.cli --ledger ledger.db attest-submit \
    --source breach-2026Q3 --token lgs_... --file leak.txt
# 声明载荷含：source、batch_id、原始文件 SHA-256、规范化记录集内容哈希、逐条记录摘要
# （仅存 sha256(40 位指纹)，原始口令与完整指纹永不进账本）

# 撤回（必须给非空理由；只有声明该批次的来源可撤回）与误报纠错
python3 -m pwncorpus.cli --ledger ledger.db attest-retract --source breach-2026Q3 \
    --token lgs_... --batch bat_... --reason "court order 2026-09-30"
python3 -m pwncorpus.cli --ledger ledger.db attest-correct --source breach-2026Q3 \
    --token lgs_... --batch bat_... --file falsepositives.txt

# 独立审计进程导出某时间点的责任快照（默认当前；--as-of 指定时刻；默认 24h 过期）
python3 -m pwncorpus.cli --ledger ledger.db ledger-snapshot --out snapshot/ [--as-of ISO8601]

# 完全离线的裁决（没有任何数据库连接；--key 可选，追加真实性校验）
python3 -m pwncorpus.adjudicate verify snapshot/ [--key ledger.db.key]
python3 -m pwncorpus.adjudicate record snapshot/ --source breach-2026Q3 \
    --fingerprint A1B2C3...   # 或 --record-sha256 <hex64>
```

账本结构与安全性质：

- **追加式签名链**：`ledger_entries` 中每条记录为 `seq / entry_id / prev_sha256 / entry_sha256 / entry_mac / payload / sealed_at`。`entry_sha256 = sha256(规范JSON{seq, prev, entry_id, payload})`，从 genesis（由 ledger_id 派生）起逐条链接；`entry_mac = HMAC-SHA256(key, entry_sha256)`。行从不更新或删除。封链时间戳在账本内**严格单调递增**（同毫秒碰撞自动 +1ms），因此撤回与纠错的先后顺序是全序，快照旧于/晚于撤回的纠错分别标注 `before_retraction` / `after_retraction`（撤回前纠错为 `while_active`）。
- **两段式持久化与中断续封**：提交先把载荷原子写入 `ledger_pending`（独立事务提交），再逐条以独立写事务封链；进程在封链中途被杀死后，剩余条目仍在暂存区，下一个写入者或独立的 `ledger-seal` 命令**从最后一个链项继续**，链无空洞、不重复。
- **重复提交返回原记录**：`(source, 规范化内容哈希)` 与显式幂等键双重判重，已封链或仍在暂存区的重复声明都返回原 `batch_id`，链上不新增条目；重复撤回/全冗余纠错同样为空操作。幂等键跨来源复用是明确冲突，绝不会返回他人批次。
- **离线裁决只凭快照 + 一条输入摘要**：快照目录为 `chain.jsonl`（截断到时间点的完整链，逐行规范 JSON）+ `snapshot.json`（重放链派生出的逐记录责任状态 + head/genesis/chain 绑定 + 自哈希 + HMAC）。`pwncorpus.adjudicate` 模块在结构上**不 import sqlite3**（有测试用阻断导入的独立进程验证）。裁决回答：是否曾由指定来源提交（可多条归属，同名记录不同批次/不同来源分别列出）、何时被撤回、撤回理由、撤回前后是否纠错。
- **快照自校验顺序**：结构字段 → 过期判定 → 链文件哈希 → 链连续性/prev 链接/(可选)逐条目 MAC → head 绑定 → **从链重放责任状态与快照声明逐字节比对** → 快照自哈希/(可选)快照 MAC。任一项失败给出明确 `FAIL:`；过期退出码 3，其余 1。
- **明确失败、不泄露桶内容**：链项缺失（跳号/断链）、链或状态被篡改、摘要不符（纠错记录不属于该批次）、来源令牌错误或越权操作他人批次、并行写锁冲突（`BEGIN IMMEDIATE` 忙等耗尽后报 `parallel write conflict`）都有明确错误。所有链级错误信息只引用 seq 与字段名；否定裁决（记录不存在或仅属他人）始终是同一最小形状 `{"submitted": false, ...}`，不能用来探测桶内容；账本数据库内不存在原始口令或完整指纹（有存储内容断言测试）。
- **快照过期与不可降级**：快照带 `expires_at`，过期后必须重新导出才能裁决；向已有快照目录导出时，较新责任状态（更高 head seq）可刷新较旧快照，**较旧快照任何情况下都不能覆盖较新状态**，同 head 的重复导出是空操作（`--force` 仅用于同级重写）。时间点快照内嵌链被截断到 cutoff，不会泄露该时刻之后的撤回理由。

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

## 测试

```bash
python3 -m unittest discover -s tests -v
```

76 个用例覆盖：并发摄取（同批次/不同批次）、批次去重不重复计数、阈值抑制小桶、阈值变更只经新版本、撤回/误报修正只经新版本生效、激活期间查询不混版、旧版本不可查但可离线验证、导出篡改检测、低于阈值桶检测、存储与 API 面均无原始口令、授权作用域、草稿陈旧检测（新增/撤回/纠错均触发）、无操作写入不误判、冲突后刷新保留版本号与阈值、激活与来源写入并发的先后语义、确认与所审草稿的清单绑定，以及增量包：分桶正确性与双清单绑定、独立检查与基线核对、应用结果与目标全量导出逐字节一致、基线不匹配/载荷篡改/清单篡改/内容缺失均拒绝、切换中与写入清单后中断的前向恢复与回滚、回滚恢复被删桶、暂存后未登记日志即掉电的前向继续与回滚清理（不留孤立暂存区、不误报已回滚）、干净镜像回滚如实报告无可回滚、混入不同增量包被拒、重复应用幂等、全部三个 CLI 入口（含库内 delta-generate）；以及来源责任账本：声明/撤回/纠错链与逐条目 HMAC、重复提交/撤回/纠错返回原记录、封链中途被杀后从最后链项续封、撤回与纠错的先后排序（撤回前/撤回后/活跃中）、时间点快照截断链与状态、快照过期、链项缺失/状态伪造/载荷篡改/错密钥拒绝、摘要不符、来源令牌错误与越权、并行写入串行成无空洞链且同批次仅一次非重复、旧快照不可覆盖较新状态、否定裁决同形且链级错误不含摘要/来源、账本存储无原始指纹、adjudicate 在阻断 sqlite3 的独立进程中可用、跨命令行/存储/审计/裁决四进程的 CLI 端到端流程。

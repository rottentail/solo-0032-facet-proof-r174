# Facet Proof 数字取证样例集

本目录是一套**可独立复核**的数字取证样例，围绕 Facet Proof 渲染服务的三类交付物做跨来源核对：

1. **审阅者看到的颜色图** —— 服务通过 `/plates/{id}/passes/color.png` 实际给出的像素字节；
2. **下载到的离线包** —— 通过 `/plates/{id}/bundle` 导出的 ZIP（含 `plate.json`、`seal.json` 与六个通道），
   并由**独立的** `facetreader`（不导入服务任何代码）复核；
3. **服务里的任务记录** —— 图版状态、审阅决定（proof/decision）、事件历史与内容寻址存储中的实际字节。

核心结论先行：**离线包内部的所有摘要都能被攻击者一并重算，因此“包内自称的哈希一致”只能证明内部一致性，
不能建立外部真实性，也不能证明服务中的当前审阅仍然有效。** 真实性必须靠跨来源（服务记录 ↔ 独立捕获 ↔ 离线包）比对建立。

---

## 1. 三个受控样例

| 样例 | 情景 | 图像字节 | 服务端状态 / 离线包 | 取证要点 |
|------|------|----------|---------------------|----------|
| **A 审阅失效** | 图版被接受后又隔离 | **完全不变** | 图版 `quarantined`，已接受审阅被改为 `invalidated` | 同样的像素与同一个有效离线包，不再代表“当前有效审阅”；包内无任何实时状态 |
| **B 曝光不同** | 同几何、同镜头、同材质，仅光照曝光不同 | 相似但不同 | 两个各自内部一致的离线包，分属不同 seal | 相似 ≠ 同一：哈希不同；服务比对显示颜色变化但轮廓/深度零变化，定位原因为光照 |
| **C 内容替换** | 对离线副本做受控篡改 | 被替换 | 朴素篡改（旧哈希）与重哈希篡改（内部自洽）两种 | 朴素篡改被读取器拒绝；重哈希后内部校验全部通过，却与服务记录不符——证明不能只信包内摘要 |

样例 A、B 使用服务正常工作流真实产出；样例 C 的篡改**只作用于离线副本**，原始包与服务数据全程只读。

---

## 2. 目录结构与证据保全

```
forensics/
├── FORENSICS.md                     本文件（方法、逐项结论、复核指引）
├── scripts/                         调查脚本（与证据分目录存放）
│   ├── client.py                    仅用标准库的 HTTP 客户端
│   ├── generate_evidence.py         经真实 HTTP 生成 A/B/C（可逐案续跑）
│   ├── tamper_bundle.py             对离线副本做两种受控篡改，原件只读
│   ├── verify_cross_source.py       跨来源核对，逐条写入可续跑账本
│   ├── build_custody.py             生成保全清单与核对汇总
│   └── run_all.sh                   一键复现整条流水线
├── evidence/
│   ├── bundles/                     6 个离线包：3 原件 + B 的第二幅 + C 的 2 个篡改件
│   ├── colors/                      独立于离线包捕获的 color.png
│   ├── transcripts/                 生成期间每一请求/响应的完整 HTTP 记录
│   ├── state/                       各案标识与基线哈希（*.done 为续跑标记）
│   └── reports/
│       ├── chain-of-custody.json    证据保全清单（逐文件 size + sha256 + 来源）
│       └── verification-summary.json 16 项核对的机器可读汇总
└── work/                            可重建的工作产物（账本、读取器输出、venv、日志）
    └── check-ledger.jsonl           追加式核对账本：中断后据此跳过已完成项
```

**保全原则**

- 服务数据根 `forensics/service-data/` 与导出包是**一次写入**的原始证据；调查脚本只读它们，
  任何“篡改”都在新建的空目录里产生**新文件**，从不覆盖原件。
- `chain-of-custody.json` 中的每个 sha256 都是对当前文件**独立重算**的结果，不是从包元数据抄录。
- 样例 C 在篡改前后都断言原始包字节一致（见账本 `original-bundle-immutable-after-tampering`）。
- HTTP 全程留痕（`transcripts/`），任何人可按顺序重放并核对响应。

---

## 3. 逐项核对结论（16 项，全部 PASS）

### 样例 A —— 图片没变，但审阅已失效

| 核对项 | 结果 | 依据 |
|--------|------|------|
| 离线包内部有效性 | PASS | `facetreader` 退出 0，六通道/元数据/PNG 语义全部自洽 |
| 图像字节未变 | PASS | 包内 `color.png` 哈希 == 服务内容寻址 blob 实际字节 == 隔离前独立捕获的 `case-a-color.png`，三者一致 |
| 服务审阅确已失效 | PASS | 图版状态 `quarantined`，proof 状态 `invalidated` |
| 离线包无法证明当前审阅 | PASS | 读取器 `trust.review_validity` 自述为 `Unknown`，`verified` 仅限内部字节完整性 |
| 事件链留痕 | PASS | 事件历史含 `quarantined` 动作 |

**结论**：像素与离线包逐字节未变，且离线包仍能通过独立读取器，但它对“审阅是否仍有效”一无所知。
图版被隔离后，HTTP 取图接口按设计返回 `409 plate_state`；此时通过图版描述符指向的内容寻址 blob
与隔离前捕获件完成三方比对，确认**变的是服务端状态，不是图像**。任何只拿着离线包的人都无法据此声称审阅仍有效。

### 样例 B —— 图像相似但曝光不同

| 核对项 | 结果 | 依据 |
|--------|------|------|
| 两个离线包各自内部有效 | PASS | `facetreader` 对 normal / bright 均退出 0 |
| 相似但非同一图像 | PASS | 两幅 `color.rgb` 的 sha256 不同；逐通道平均字节差约 11.6，尺寸完全相同 |
| 根因在光照（seal 不同） | PASS | 两个 `seal_hash` 不同，而 `lens_hash` 相同——镜头几何一致，差异来自照明闭包 |
| 服务记录与离线包相符 | PASS | 两图版描述符 → 内容寻址 blob 的实际字节，分别等于两个包内 `color.png` |
| 服务比对量化曝光差异 | PASS | `color_changed=1716`，`silhouette_changed=0`，`depth_changed=0` |

**结论**：两图轮廓与深度**零差异**、仅 1716 个像素颜色变化，精确对应“同场景、不同曝光”。
仅凭肉眼“看起来差不多”会误判为同一图；内容哈希与服务侧比对把“相似”与“同一”严格区分开，
并把原因定位到冻结闭包中的光照参数，而非几何或镜头。

### 样例 C —— 内容替换（受控篡改）

| 核对项 | 结果 | 依据 |
|--------|------|------|
| 原始包基线有效 | PASS | 原件 `facetreader` 退出 0 |
| 朴素篡改被拒绝 | PASS | 只换像素、保留旧描述符 → 退出 2，错误码 `channel_size`（进而还有哈希/PNG 不符） |
| 重哈希篡改“内部通过” | PASS（符合预期） | 重算通道描述符与 `visual_hash` 后，读取器退出 0——**内部完全自洽** |
| 重哈希件与服务记录不符 | PASS | 伪造 `visual_hash` ≠ 服务图版 `visual_hash`；同时服务对原件自检仍 `valid` |
| 重哈希件颜色字节与服务不符 | PASS | 伪造 `color.png` 哈希 ≠ 服务 blob 实际字节 |
| 原件在篡改后保持不变 | PASS | 当前 sha256 == 生成时记录的基线 sha256 |

**结论（关键）**：

- **朴素篡改**会被独立读取器当场拒绝，因为陈旧的自报摘要与新字节对不上。
- **重哈希篡改**能让包内每一条哈希链都自洽，从而通过所有**内部**校验——这正说明
  `facetreader` 的信任边界只到“内部一致性”。检测它的唯一办法是**跨来源**：把包内 `visual_hash`
  与颜色字节拿去和**服务里的权威记录**比对，二者立即冲突。
- 因此，**绝不能仅凭包内自称的摘要建立信任**；离线包是“事实快照”，不是“真实性证明”。

---

## 4. 为什么不能只信包内摘要（信任边界）

`facetreader/format.py` 的 `TRUST` 明确自述其四个边界，本样例集逐条实证：

| 读取器自述 | 含义 | 本集对应证据 |
|------------|------|--------------|
| `verified` = 仅内部字节与元数据一致 | 包内哈希只能证明“包没被局部损坏” | C 的重哈希件内部全过却系伪造 |
| `external_authenticity` 未建立 | 攻击者可连内容带全部哈希一起替换 | C 重哈希件 `visual_hash` 被成功伪造 |
| `review_validity` 未知 | ZIP 不含 proof 记录与实时隔离状态 | A 的包有效但服务审阅已 `invalidated` |
| `render_correctness` 未建立 | 只解码/交叉核对通道，不独立重渲染 | B 两包都有效，但是两幅不同曝光的图 |

可信结论需要**三个独立来源互相印证**，任一来源单独都不充分：

```
服务权威记录（图版/proof/事件 + 内容寻址 blob 实际字节）
            │  描述符哈希比对
            ▼
独立捕获的颜色图  ◀── 字节比对 ──▶  离线 ZIP（独立 facetreader 复核）
```

---

## 5. 中断与续跑（调查不丢进度）

- `generate_evidence.py` 每案写 `evidence/state/case-*.done`；重跑时已完成的案件直接跳过，不重新生成、不改写证据。
- `verify_cross_source.py` 把每条核对**追加**到 `work/check-ledger.jsonl`，每完成一条即落盘。
  重跑时按 `(案件, 核对项)` 去重，已完成项跳过。
- 已实测：把账本截断到仅剩前 2 条后重跑，脚本补齐其余 14 条，**所有离线包字节前后完全一致**，
  最终账本与一次完整运行逐条相同。
- 服务自身的渲染进度（分块租约）与本调查账本相互独立；调查中断不影响服务数据，反之亦然。

---

## 6. 如何独立复核

前置：Python 3.11+，仅标准库；在仓库根目录操作。

```sh
# 一键复现（启动隔离服务 → 生成 → 篡改副本 → 跨来源核对 → 保全清单）
bash forensics/scripts/run_all.sh

# 或分步执行
python3 -m facetproof --root ./forensics/service-data --host 127.0.0.1 --port 8796 &
python3 -I forensics/scripts/generate_evidence.py
python3 -I forensics/scripts/tamper_bundle.py
python3 -I forensics/scripts/verify_cross_source.py     # 可重复运行，自动续跑
python3 -I forensics/scripts/build_custody.py

# 直接用独立读取器手工复核任意一个包（退出 0=内部一致，2=拒绝）
python3 -m facetreader forensics/evidence/bundles/case-c-tampered-naive/plate-bundle.zip;   echo $?
python3 -m facetreader forensics/evidence/bundles/case-c-tampered-rehashed/plate-bundle.zip; echo $?
```

复核要点：

1. 用 `chain-of-custody.json` 中的 sha256 自行 `sha256sum` 比对，确认证据未被改动；
2. 对 6 个包分别运行 `facetreader`，观察原件/重哈希件退出 0、朴素篡改件退出 2；
3. 按 `transcripts/` 中的 HTTP 顺序核对服务端响应；
4. 对照 `work/check-ledger.jsonl` 与 `reports/verification-summary.json` 复查 16 项结论；
5. 读取器在隔离解释器（`-I`，且通过 venv 的 `.pth` 仅指向本仓库）中运行，
   使被调查的 ZIP 路径成为唯一外部输入，避免包内植入模块干扰解释器。

> 说明：`forensics/service-data/` 与 `forensics/work/` 是可重建的运行/工作产物；
> 权威交付证据在 `forensics/evidence/`。删除前两者后用 `run_all.sh` 可重新生成整套样例。

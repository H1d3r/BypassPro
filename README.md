![](https://avatars.githubusercontent.com/u/87968663?s=200&v=4)

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。
### 介绍
作者：[p0desta](https://github.com/p0desta/)，[Y0!0](https://github.com/hooray195)，[0cat ](https://github.com/0cat-r) 

团队：[0x727](https://github.com/0x727)，未来一段时间将陆续开源工具，地址：[https://github.com/0x727](https://github.com/0x727)

定位：在攻防和渗透测试中，可以更加方便的找到一些绕过的点，比如403bypass,比如shiro的权限绕过

语言：Java 8（`pom.xml` 中 `source/target=8`，产物可在 Java 8 环境运行；构建可使用 JDK 8+）

功能：权限绕过的自动化bypass的burpsuite插件。

此项目是基于p0desta师傅的项目[https://github.com/p0desta/AutoBypass403-BurpSuite](https://github.com/p0desta/AutoBypass403-BurpSuite)进行二开的。用于权限绕过，403bypass等的自动化bypass的Burpsuite插件。感谢p0desta师傅的开源，本二开项目已经过p0desta师傅本人允许开源。

### 当前版本BypassPro 4.0 更新

#### 新增功能

**1. 新增 Mode 2: Auto WAF Bypass（自动 WAF 绕过）**

右键 `Send to BypassPro (WAF)` 触发，自动对请求 Body 进行多种编码变形绕过 WAF：

- Body 字符集编码：UTF-16 / UTF-16BE / UTF-16LE / UTF-32 / UTF-32LE / IBM037 / cp290
- Body 压缩：Gzip 压缩请求体，同时设置 `Content-Encoding: gzip`
- Content-Type 欺骗：
  - `multipart/form-data`：表单参数自动拆解为标准 multipart 格式；非表单类型做 Header 欺骗
  - `text/plain`：伪装 Content-Type 绕过 WAF 对 JSON/XML 的检测
- 每种变形生成独立变体请求，结果经相似度过滤后入表

**2. 新增 Mode 3: Manual WAF Bypass（手动 WAF 工作台）**

右键 `Send to BypassPro (Manual WAF)` 将请求送入工作台，类似 Repeater 但专为 WAF 绕过设计：

- 编辑器：使用 Burp 原生 IMessageEditor，支持 Raw/Hex 视图，可处理二进制/Gzip 数据
- 目标可编辑：Host/Port/HTTPS 输入框，支持测试 Host 头欺骗或切换目标
- Transform Tools（变换工具）：
  - Encoding：URL Encode/Decode、Double URL、Base64、Hex、Unicode Escape
  - Case：UPPER、lower、RaNdOm 随机大小写
  - Unicode：全角字符、同形字 (Homoglyph)
  - SQL Bypass：`/**/` 包裹、`/*!50000*/` 版本注释、空白转 `/**/`
  - Path：`../` 插入、`..;/` Tomcat 绕过
  - Dirty Data：`{{dirty(N)}}` 随机数字、`{{dirtynull(N)}}` NUL 字节（发送时展开）
  - Request：Gzip 压缩、To Multipart 转换、HTTP/1.0 降级、字符集编码（UTF-16/32/IBM037 等）
- 发送控制：
  - Send / Cancel 按钮，支持中断请求
  - Follow Redirect 开关，控制是否跟随 301/302/303/307/308（最多 10 跳）
  - Ctrl+Enter / Cmd+Enter 快捷发送
- 状态栏：显示 Status Code / Time(ms) / Request Size / Response Size / Redirect 次数
- History：
  - 显示 Method / Path / Status / Length / Time(ms) / 时间戳
  - 双击或右键可将历史请求加载回编辑器继续修改
  - 最多保留 50 条，Undo/Redo 最多 20 步
- 结果记录：不做相似度过滤，所有发送都写入 History 和 Dashboard

**3. UI 重构**

- 页签拆分：Dashboard（结果表格 + Request/Response 双窗格）/ Config（配置管理）/ Manual WAF（手动工作台）
- 进度显示：Dashboard 顶部增加动画进度条 + 完成数/总数
- Auto Scan：勾选后监听 Proxy 响应，命中 401/403 时自动触发扫描
- 右键菜单拆分：
  - `Send to BypassPro (Access Control)`：访问控制绕过
  - `Send to BypassPro (WAF)`：WAF 绕过（Body 编码变形）
  - `Send to BypassPro (Manual WAF)`：送入手动工作台

**4. 配置文件升级（参考 HaE）**

- 外置配置：`~/.config/BypassPro/BypassPro-config.yaml`
- 首次启动：若外置文件不存在，从 jar 内置模板自动生成
- 更新插件不覆盖：只有点击 Config 页的 Reinit 并确认才会重置
- Config 页面：支持 Reload（重新加载）/ Reinit（恢复默认）/ 当前规则展示

#### 优化与修复

**Mode 1 (Access Control)**
- HTTP-Version 处理：修改版本号时不再清空原有 Headers

**Mode 2 (WAF)**
- Body 二进制安全：使用 ISO_8859_1 处理，不破坏二进制数据
- Content-Type charset：正则替换已有 charset，不会出现 `charset=utf-8; charset=utf-16`
- CL-TE 冲突：修改 Body 后自动移除 `Transfer-Encoding` 头
- Multipart 智能转换：表单参数拆解还原，非表单做 Header 欺骗
- 重定向保留 Payload：跟随重定向时传入已编码的 Body

**Mode 3 (Manual)**
- 脏数据与 CL：检测用户是否手动修改了 Content-Length（用于 CL-TE 测试），若已修改则不自动覆盖
- HTTP/1.0 降级：完整清洗 Keep-Alive / Transfer-Encoding / Connection 头
- Gzip 防双重压缩：检查 Header 和 Magic Bytes (1F 8B)，已压缩时提示

**全局**
- 线程池：全局单例 ExecutorService，避免线程爆炸
- 内存保护：History 最多 50 条，Undo/Redo 最多 20 步
- 并发安全：Dashboard 表格写入加锁，避免多线程竞争

### 用法

#### 工作模式（Modes）

本插件围绕“**把同一个目标请求快速变形并重放**”来提高发现绕过点的效率。不同模式的区别主要是：**触发方式**、**使用的规则集（profile）**、**是否做相似度过滤**、**结果如何落表**。

##### 1）Auto Scan（自动触发 / 访问控制）
- **入口**：`Dashboard` 页勾选 **Auto Scan**
- **触发方式**：监听 Proxy 响应；当响应状态码命中 `401/403` 时自动触发
- **规则集**：固定使用 `profiles.access_control`（不会跑 WAF profile）
- **静态资源过滤**：对常见静态后缀不触发（避免噪声与额外请求）
- **用途定位**：批量找 401/403 访问控制绕过点（如 403 bypass、权限绕过）

##### 2）主动 Auth Bypass（自动 / 访问控制）
- **入口**：在 Proxy/Target 等视图选中请求右键 **Send to BypassPro (Access Control)**
- **规则集**：`profiles.access_control`
- **用途定位**：对“你指定的某一个请求”做访问控制绕过变形与重放（比 Auto Scan 更可控）

##### 3）主动 WAF Bypass（自动 / 规则集）
- **入口**：右键 **Send to BypassPro (WAF)**
- **规则集**：优先使用 `profiles.waf`；当配置未提供 `waf` profile 时会回退到 `profiles.access_control`
- **用途定位**：对“你指定的某一个请求”按 WAF 规则集做路径/头部等自动变形（适合验证被拦截页/风控页的差异）

##### 4）主动 WAF Bypass（手动 / 工作台）
- **入口**：右键 **Send to BypassPro (Manual WAF)**（把选中的请求送入 `Manual WAF` 页签）
- **交互方式**：在工作台里直接编辑请求；选中文本后点击右侧/下方的变换工具进行变形；点击 **Send** 发送
- **结果记录**：手动模式不做相似度过滤；每次 Send 都会记录到 **History**，同时写入 Dashboard（`Tool` 列会标记为 `WAF Bypass (Manual)`）
- **用途定位**：面向“研究型绕过”，适合逐步试探、组合变形、观察差异

#### 模式背后的核心逻辑（How it works）

##### A. 变形规则如何生成
- 自动模式的变形主要来自配置文件 `profiles.<profile>`（`access_control`/`waf`）：
  - **suffix**：对路径尾部追加变体（如 `/.`、`;/.css`、`%09` 等）
  - **prefix**：对路径的每一层目录做前缀变体（如 `;/`、`%2e/`、`images/..;/` 等）
  - **boundary_insert**：在目录边界插入标记（一次只改一个边界，避免组合爆炸）
  - **headers**：伪造/注入 Header 变体（如 `X-Forwarded-For`、`X-Client-IP` 等）

##### B. 自动模式如何回显/落表（减少噪声）
- **落表候选状态码**：变体请求（如遇 30x 会跟随重定向，最多 2 跳）最终响应状态码命中以下集合时，才进入“可能入表”的判断：  
  `200/206/304/301/302/303/307/308/405/415`
- **入表判定**：同时满足：
  - **候选状态码命中**（见上）
  - 且满足以下任意一条：
    - **相似度低于阈值**：变体响应 body 与原始响应 body 的相似度 \(ratio\) 满足 `ratio < threshold`
    - **状态码类别变化**：原始与变体的状态码“百位段”不同（例如 `403 -> 302`、`401 -> 200`）
- **相似度阈值来源**：统一由 `general.similarity_threshold` 管理（在 `Config -> General` 设置）
  - **0-1 含义**：表示“变体响应与原始响应的相似程度”（越接近 1 越相似）
  - **值越大**：更容易满足 `ratio < threshold`，因此更容易入表（更宽松，噪声可能更多）
  - **值越小**：更不容易入表（更严格，只保留差异更大的响应）

##### C. 手动模式为什么不做相似度过滤
- 手动模式的价值在于“人”在迭代选择变形与观察差异，所以工作台会保留所有尝试，方便回溯与对比。

##### D. 手动模式的变换工具（Transform Tools）
- Transform Tools 会对“你选中的文本”做编码/变形（如 URL/Base64/Unicode、大小写、全角/同形字、SQL 注释变形、路径变形等）。
- 为避免插入超大脏数据导致 Burp 卡顿，工作台支持用占位符插入脏数据：
  - `{{dirty(N)}}`：发送时生成 N 位随机数字
  - `{{dirtynull(N)}}`：发送时生成 N 个 NUL 字节
  - 发送前会展开占位符并重算 `Content-Length`，保证实际发包字节与长度一致

#### 内置规则（不可配置）

以下规则硬编码在插件中，用户无法修改：

| 规则 | 值 | 说明 |
|------|-----|------|
| Auto Scan 触发状态码 | 401, 403 | Proxy 响应命中这些状态码时触发扫描 |
| 落表候选状态码 | 200, 206, 304, 301, 302, 303, 307, 308, 405, 415 | 变体响应状态码必须在此范围才可能入表 |
| 自动模式重定向跳数 | 最多 2 跳 | 跟随 30x 重定向的最大次数 |
| Manual 模式重定向跳数 | 最多 10 跳 | Follow Redirect 开启时的最大次数 |
| History 最大条数 | 50 条 | 超出后自动删除最旧记录 |
| Undo/Redo 最大步数 | 20 步 | 超出后自动丢弃最旧状态 |
| 静态资源过滤后缀 | .js, .css, .png, .jpg, .gif, .ico, .svg, .woff 等 | Auto Scan 不扫描这些后缀 |

#### 快速开始（推荐流程）
- **先用 Auto Scan**：快速覆盖站点常见的 401/403 场景，找“可能绕过点”
- **对可疑请求用主动模式复测**：右键发起 `Access Control` 或 `WAF`
- **需要精细化研究时用 Manual WAF**：把请求送入工作台，多轮变形与对比

### 构建

- Maven 打包：
  - `mvn -DskipTests package`
  - 产物位于 `target/`

### 注意事项
- Auto Scan 会对命中条件的 Proxy 响应自动发起一批变体请求，目标站点存在 WAF/频率限制时建议关闭 Auto Scan，仅使用手动扫描。

### 案例
### 案例 1
之前很多案例没有记录。这次bypasspro又发现了一个

最近的JumpServer未授权访问漏洞(CVE-2023-42442)：未经身份验证的远程攻击者利用该漏洞可以访问录像文件，远程获取到敏感信息。

目前各大CERT给出的payload是/api/v1/terminal/sessions/ 或者/api/v1/terminal/sessions/?limit=1

部分企业可能无法及时升级版本，在nginx或者其他设备做防护处理。

比如访问原始payload
<img width="985" alt="image" src="https://github.com/0x727/BypassPro/assets/49912303/bac05da4-451a-4b8e-a66a-32b17a20a1d2">


ok BypassPro给出 bypass 的payload：/api/v1/terminal/sessions.json?limit=1

![image](https://github.com/0x727/BypassPro/assets/49912303/361abfdd-58c3-4465-962b-6f747dc1d355)

####案例 2

<img width="505" height="162" alt="image" src="https://github.com/user-attachments/assets/64aa6617-dc34-4222-9ba7-7c717cb3df79" />

emmm这个时候还是老版本，
<img width="1433" height="730" alt="image" src="https://github.com/user-attachments/assets/b069b278-745f-4c38-bf0c-5d5627136b77" />










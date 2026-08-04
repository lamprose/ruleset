# 🛠️ DIY-Ruleset - 构建适合自己的规则集

DIY-Ruleset 是一个网络代理规则集处理引擎，通过 GitHub Actions 工作流每天自动拉取各个上游的优质规则，进行深度去重、清洗和精准剔除，按需生成 **Sing-box**、**Mihomo (Clash Meta)**、**Surge / Shadowrocket / Quantumultx / Loon / Egern / Stash** 以及 **DNS 服务端** 等多格式规则集。最终生成的文件将推送到 `publish` 分支，并生成一份包含精确计数统计和下载链接的 Markdown 报表。

<details>

<summary>📂 <strong>查看项目文件结构</strong></summary>

```text
DIY-Ruleset/
├── .github/workflows/     # GitHub Actions
│   └── run.yml            # 核心执行脚本
├── add/                   # 规则补充目录
├── remove/                # 规则剔除目录
├── core/                  # 核心代码
│   ├── compiler.go        # 负责编译文件
│   ├── config.go          # 配置解析模块
│   ├── exporter.go        # 规则集导出模块
│   ├── fetcher.go         # 并发网络模块
│   ├── parser.go          # 多语法解析器
│   ├── processor.go       # 规则处理模块 
│   ├── report.go          # 负责生成报表
│   └── run_test.go        # 配置校验模块
├── config-example.yaml    # 配置示例文件
├── config.yaml            # 主配置文件
├── main.go                # 主程序入口
├── go.mod                 # Go模块依赖包文件
└── README.md              # 项目使用说明文档

```

</details>

---

## 🚀 快速开始 (Fork)

只需简单几步，即可拥有属于你自己的每日更新规则库：

1. 点击页面右上角的 **Fork** 按钮，将本仓库克隆到你的 GitHub 账号下。
2. 进入你仓库的 `Settings` -> `Actions` -> `General`，确保 **Workflow permissions** 设置为 `Read and write permissions`。
3. 打开根目录的 `config.yaml`，按需修改你喜欢的规则源和文件输出格式。
4. 进入 `Actions` 页面，在左侧选择 `Build Custom Rules`，然后点击右侧的 `Run workflow` 手动运行一次。
5. 等待约 1-2 分钟运行完毕，切换到 `publish` 分支，你就能看到生成的所有规则文件和统计报表了！

---

## 📂 自定义规则 (add & remove 指南)

如果你发现上游规则有遗漏或者误杀，无需等待上游作者更新，你可以直接通过本地文件夹实现增删。引擎会在处理对应规则集时，自动去这两个文件夹寻找同名的 .list 文件进行合并与剔除。

### ➕ 添加规则 (`add/` 目录)
如果你想给名为 `proxy` 的规则集补充规则：
* 在 `add/` 文件夹下新建文件 `proxy.list`。
* 在里面写入你的规则，引擎会自动将它们合并到最终输出文件。

### ➖ 剔除规则 (`remove/` 目录)
如果你发现上游把某个正常的网站（比如 `baidu.cn`）拦截了，你想把它剔除掉：
* 在 `remove/` 文件夹下新建对应的 `.list` 文件（如 `reject.list`）。
* 写入规则，引擎会在去重阶段精准将其剔除。

### 语法规则 (必看)
在这两个文件夹里，建议使用 Clash 标准语法或快捷语法：

* **默认简写**：只写域名 `google.com`，引擎会默认当做 `DOMAIN,google.com` 处理。
* **快捷前缀**：写 `+.google.com`，引擎会自动等同于 `DOMAIN-SUFFIX,google.com` (匹配其及所有子域名)。
* **Clash 通配符**：带有 `*` 号或 `.` 号前缀（如 `*.google.com`、`.google.com`），引擎会自动转换为严谨的正则表达式匹配。
* **其它 Clash 语法**：支持 `DOMAIN-KEYWORD,google`、`IP-CIDR,1.1.1.1/32`、`PROCESS-NAME,v2ray.exe` 等大部分标准语法。（部分较少用到的语法不支持）

## 连坐 or 精准 (EXACT:)
在 `remove/` 文件夹中剔除规则时，引擎默认使用的是（**连坐机制**）：
* 如果你写 `DOMAIN-SUFFIX,cn`，引擎会将所有包含 `.cn` 后缀的域名（如 `baidu.cn`, `qq.cn` 以及 `.cn` 本体）全部剔除。

如果你只想单独删掉上游列表里一条特定的规则，而不影响其他带有相同后缀的域名，你可以使用 **精确命中 `EXACT:`** 方式：
* 写法：`EXACT:DOMAIN-SUFFIX,cn`
* **效果**：引擎只会将上游中完全等于 `DOMAIN-SUFFIX,cn` 的这一行剔除，而 `baidu.cn` 等规则将**不受影响**。

---

## ⚙️ 核心配置详解 (`config.yaml`)

所有的规则配置都在 `config.yaml` 中，运行时会进行配置参数校验。global 里的配置是所有规则集的默认设置。如果你想让某个规则集（比如 cn）具有特殊的输出行为，直接在该 Category 下复写对应的客户端开关即可，其余参数会自动继承全局。

### 1. 输出文件控制
所有支持的客户端（如 `singbox`, `mihomo`, `surge`, `Loon` 等）均支持独立的输出控制：
* `enable: true/false`：控制是否生成该客户端的规则文件。
* `single_file: true/false`：设置为 `true` 时，引擎会将域名规则和 IP 规则混合打包输出为一个文件。设置为 `false` 时，引擎会将域名规则和 IP 规则分为两个独立文件。

### 2. 智能解析器
 `parser` 引擎支持智能嗅探解析多种复杂的上游源格式。你可以不指定 `parser` 参数，引擎会自动推导；或者你可以显式指定一种格式，可用值为：`clash`, `v2ray`, `adblock`, `hosts`, `dnsmasq`, `smartdns`, `surge`, `shadowrocket`, `quantumultx`, `loon`, `stash`, `egern`, `white`。


### 3. DNS 防护与智能分流
 Dnsmasq 和 SmartDNS 格式既可以用来去广告，也可以用来做路由分流：
* **拦截模式**：默认情况下，输出为 `address=/domain/0.0.0.0`。
* **分流模式**：如果你在配置中指定了 Server（例如 `dnsmasq_server: "223.5.5.5"`），引擎会自动将其转换为分流转发语法 `server=/domain/223.5.5.5`。

### 4. 白名单行为控制
对于 `reject` 去广告规则，若上游为 adblock 类型规则并带有 `@@` 的白名单规则时，可开启 `auto_extract_white: true` ，会提取上游带有 `@@` 的白名单规则，并且可以控制它的行为：
* `white_behavior: "remove"`（默认）：提取出白名单，**并将它们从原拦截规则中抵消/剔除**。
* `white_behavior: "extract_only"`：仅提取出白名单规则，**不干预原拦截规则*。

---

## ⚠️ 注意事项

**Mihomo (`.mrs`) 编译限制**：
   Mihomo 官方内核对 `.mrs` 二进制格式的类型要求极其严苛。仅支持完整域名、通配符域名和 IP 规则。如果你发现 `.mrs` 文件内的条目数量与 `.yaml` 文本列表有出入，这属于上游内核的编译机制限制。并且 `.mrs` 二进制格式文件不支持将 domain 和 ip 规则混合打包，即便开启 `single_file: true`，引擎仍会强制对其进行拆分。
# tiktok-ssl-bypass-skill

> 绕过 **Cronet / BoringSSL** 证书校验的 [Claude Code](https://docs.claude.com/en/docs/claude-code) 技能,配合 **Frida + IDA MCP** 快速为 TikTok / 抖音等字节系 App 生成对应版本的 SSL Pinning 绕过脚本。

English: [README_EN.md](README_EN.md)

---

## ⚠️ 免责声明

本项目仅用于**授权的安全测试、协议分析与学习研究**(你自己的设备、你自己的流量、CTF、合规渗透)。使用者需遵守当地法律法规,严禁用于任何商业或非法用途。由此产生的一切后果由使用者自行承担,与作者无关。

---

## 为什么普通 SSL 绕过对 TikTok 无效?

TikTok / 抖音使用 Google 的 **Cronet** 网络栈(从 Chromium 剥离出的 SDK,打包为 `libsscronet.so`)。证书校验(含 SSL Pinning)完全在 **Native 层**通过 BoringSSL 的 `SSL_CTX_set_custom_verify` 完成——**低于 Java 层**。

所以 Java 层的常规手段(JustTrustMe、okhttp hook、系统信任用户 CA)**统统无效**。表现为:网络正常,但 App 报错、代理里看到 `certificate_unknown`。

**核心原理:** `SSL_CTX_set_custom_verify(ctx, mode, callback)` 的第三个参数 `callback` 是应用自定义的校验回调,返回 `0` 表示成功(`ssl_verify_ok`)。Hook 这个回调、强制返回 `0`,即可全局绕过。

```
Java API → JNI → Cronet C API → Chromium net stack → BoringSSL(SSL_CTX_set_custom_verify)
```

详细逆向思路见技能文档:[`skills/rev-cronet-ssl/SKILL.md`](skills/rev-cronet-ssl/SKILL.md)

---

## 仓库内容

| 文件 | 说明 |
|------|------|
| `skills/rev-cronet-ssl/SKILL.md` | 技能主文件:激活触发器、检测原理、**IDA MCP 逆向工作流**、绕过策略决策树 |
| `skills/rev-cronet-ssl/assets/cronet_ssl_bypass.js` | **通用模板**:多模块、dlopen + 轮询双探测,导出 + offset 双策略,需按目标版本微调 `CONFIG` |
| `skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js` | **开箱即用实例**:已在 TikTok `45.7.1` 实测通过,带轮询探测与经 IDA 确认的 offset |

### 两个脚本怎么选?

- **想直接抓 TikTok 45.7.1** → 用 `tiktok_ssl_bypass.js`,无需改动。
- **其它版本 / 抖音 / 其它字节系 App** → 用 `cronet_ssl_bypass.js` 通用模板,按 SKILL.md 的 IDA MCP 流程定位当前版本的导出/offset 后填入 `CONFIG`。

> 网上现成的脚本大多依赖 hook `android_dlopen_ext` 来等 so 加载——但**新版字节系用 bytehook/自定义加载器,该 hook 不触发**,脚本会静默失效。本仓库的脚本改用**轮询**探测模块,规避了这个坑。

---

## 快速开始

### 前置条件

- 已 root 的 Android 设备 / 模拟器,系统已信任你的抓包代理 CA
- 设备上运行 `frida-server`(或 gadget),PC 端 `frida` 工具
- 抓包代理(mitmproxy / Charles / BurpSuite)

### 运行(以 TikTok 为例)

```bash
# spawn 模式(-H 走网络转发到 frida-server;本机 usb 用 -U)
frida -U -f com.zhiliaoapp.musically \
      -l skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js

# 抖音
frida -U -f com.ss.android.ugc.aweme \
      -l skills/rev-cronet-ssl/assets/cronet_ssl_bypass.js
```

> 新版 Frida CLI **没有 `--no-pause`**,加载脚本后进程会自动恢复运行。

### 命中成功的输出

```
[tiktok-ssl] hook SSL_CTX_set_custom_verify @ 0x... (libsscronet.so!0x4b2580)
[tiktok-ssl] SSL_CTX_set_custom_verify hit | caller=libsscronet.so!0x... | mode=0x1 | cb=0x...
[tiktok-ssl] force verify 0x1 -> 0 (ssl_verify_ok) [export]
```

看到 `force verify ... -> 0` 且代理开始出流量,即绕过成功。

---

## 作为 Claude Code 技能使用

配合 [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp),让 Claude 自动完成"加载 so → 定位 `SSL_CTX_set_custom_verify` → 确认校验回调 → 算出 offset → 生成对应版本脚本"的全流程。

安装(把技能软链到你项目的 `.claude/skills/`):

```bash
git clone https://github.com/Zskkk/tiktok-ssl-bypass-skill.git
ln -s "$(pwd)/tiktok-ssl-bypass-skill/skills/rev-cronet-ssl" \
      /path/to/your-project/.claude/skills/rev-cronet-ssl
```

之后在 Claude Code 里让它 "用 rev-cronet-ssl 配合 IDA MCP 给出绕过 TikTok SSL 的 frida 脚本" 即可。

---

## 适用范围

| App | 包名 | 主模块 |
|-----|------|--------|
| TikTok | `com.zhiliaoapp.musically` | `libsscronet.so` |
| 抖音 | `com.ss.android.ugc.aweme` | `libsscronet.so` |

TikTok 与抖音共用同一套协议栈,思路互通(仅 offset 因版本而异)。TikTok 地区限制:拔 SIM 卡 + 设备语言/时区改海外 + IP 走海外。

## 版本适配说明

- 导出式策略(hook `SSL_CTX_set_custom_verify` 改回调返回值)一般能扛过**小版本**更新。
- fallback 的 offset 是**锁死具体版本**的,大版本变了需用 IDA 重新定位。
- QUIC-only 接口即使绕过 pinning 也可能逃过 HTTP 代理,那是协议层问题,非 pinning 问题。

## License
MIT

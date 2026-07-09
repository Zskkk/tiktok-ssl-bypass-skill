# tiktok-ssl-bypass-skill

> 绕过 **Cronet / BoringSSL** 证书校验的 [Claude Code](https://docs.claude.com/en/docs/claude-code) 技能,配合 **Frida + IDA MCP** 快速为 TikTok / 抖音等字节系 App 生成对应版本的 SSL Pinning 绕过脚本。

English: [README_EN.md](README_EN.md)

---

## ⚠️ 免责声明

本项目仅用于**授权的安全测试、协议分析与学习研究**(你自己的设备、你自己的流量、CTF、合规渗透)。使用者需遵守当地法律法规,严禁用于任何商业或非法用途。由此产生的一切后果由使用者自行承担,与作者无关。

---

**核心原理:** `SSL_CTX_set_custom_verify(ctx, mode, callback)` 的第三个参数 `callback` 是应用自定义的校验回调,返回值枚举 `0=ok / 1=invalid / 2=retry`。用 `Interceptor.attach` 在回调的 `onLeave` 里**仅把失败 `1` 改成 `0`**(放行异步信号 `2`,不替换整个回调),即可绕过校验且不破坏 Cronet 状态机。

```
Java API → JNI → Cronet C API → Chromium net stack → BoringSSL(SSL_CTX_set_custom_verify)
```

详细逆向思路见技能文档:[`skills/rev-cronet-ssl/SKILL.md`](skills/rev-cronet-ssl/SKILL.md)

---

## 仓库内容

| 文件 | 说明 |
|------|------|
| `skills/rev-cronet-ssl/SKILL.md` | 技能主文件:激活触发器、检测原理、**IDA MCP 逆向工作流**、绕过策略决策树 |
| `skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js` | **绕过脚本**:已在 TikTok `45.7.1` 实测通过,也适用于抖音等 Cronet App。按符号名在 App 自带 BoringSSL 中定位(排除系统 `libssl.so`)、轮询 + dlopen 双探测、跳过 QUIC 回调、按地址去重、仅 `1→0`;含 offset 兜底与 backtrace 调试开关 |

---

## 快速开始

### 前置条件

- 已 root 的 Android 设备 / 模拟器,系统已信任你的抓包代理 CA
- 设备上运行 `frida-server`(或 gadget),PC 端 `frida` 工具
- 抓包代理(mitmproxy / Charles / BurpSuite)

### 运行(以 TikTok 为例)

```bash
# spawn 模式(本机 USB 用 -U;走网络转发到 frida-server 用 -H host:port)
# 必须 spawn(-f):SSL_CTX 在启动早期创建,attach 太晚会 hook 不到
frida -U -f com.zhiliaoapp.musically \
      -l skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js

# 抖音(同一个脚本)
frida -U -f com.ss.android.ugc.aweme \
      -l skills/rev-cronet-ssl/assets/tiktok_ssl_bypass.js
```

运行脚本后 hook 生效:

![运行 Frida 脚本](./docs/run-frida.png)

### 效果

Charles 成功抓到 App 流量:

![抓包效果](./docs/capture-result.png)

---

## 作为 Claude Code 技能使用

配合 [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp),让 Claude 自动完成"加载 so → 定位 `SSL_CTX_set_custom_verify` → 确认校验回调 → 算出 offset → 生成对应版本脚本"的全流程。

安装(把技能软链到你项目的 `.claude/skills/`):

```bash
git clone https://github.com/Zskkk/tiktok-ssl-bypass-skill.git
ln -s "$(pwd)/tiktok-ssl-bypass-skill/skills/rev-cronet-ssl" \
      /path/to/your-project/.claude/skills/rev-cronet-ssl
```

之后在 Claude Code 里让它 "用 rev-cronet-ssl 配合 IDA MCP 给出绕过 TikTok SSL 的 frida 脚本并放在当前目录下" 即可。

![Claude 生成脚本](./docs/claude-generate.png)

---

## 适用范围

| App | 包名 | 主模块 |
|-----|------|--------|
| TikTok | `com.zhiliaoapp.musically` | `libsscronet.so` |
| 抖音 | `com.ss.android.ugc.aweme` | `libsscronet.so` |

TikTok 与抖音共用同一套协议栈,思路互通(仅 offset 因版本而异)。TikTok 地区限制:拔 SIM 卡 + 设备语言/时区改海外 + IP 走海外。

---

## 许可协议

[MIT](LICENSE)

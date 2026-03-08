# XClaw AgentGuard 安全检测框架

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

为 AI 智能体应用提供安全检测能力的 Python 库，包含 12 个专用检测器，用于识别提示注入、越狱攻击、命令注入等威胁。

## 这是什么

**XClaw AgentGuard** 是一个开发库，不是开箱即用的安全产品：

- **检测工具** — 供开发者在代码中调用
- **可选辅助进程** — 提供便利封装（核心功能不依赖）
- **自我保护** — 监控框架自身文件完整性

**这不是：**
- ❌ 无需代码改动就能自动防护的系统
- ❌ 透明拦截所有流量的安全层
- ❌ 绝对安全的保证（没有系统能做到）

## 架构概览

```
┌─────────────────────────────────────────┐
│              你的应用                    │
│  ┌─────────┐  ┌─────────────────────┐  │
│  │ 用户输入 │  │  工具调用 / 外部数据  │  │
│  └────┬────┘  └──────────┬──────────┘  │
│       └───────────────────┘             │
│                    │                     │
│       你调用：detector.detect(input)     │
│       （需要显式集成）                    │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         XClaw AgentGuard 框架           │
│  ┌─────────────────────────────────┐   │
│  │  检测库（始终可用）              │   │
│  │  • 12 个威胁检测器               │   │
│  │  • 模式匹配与分析                │   │
│  │  • 置信度评分                    │   │
│  └─────────────────────────────────┘   │
│                    │                    │
│  ┌─────────────────┴───────────────┐   │
│  │  可选：辅助进程（需装 [engine]） │   │
│  │  • 常用场景的便利封装            │   │
│  │  • 不装也能用核心功能            │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## 安装

### 推荐方式：OpenClaw

```bash
openclaw skills install https://github.com/neil-njcn/xclaw-agentguard-framework
```

适合 OpenClaw 智能体，自动注册检测器，与智能体生命周期集成。

### 备选：pip

```bash
# 核心功能（12 个检测器）
pip install xclaw-agentguard-framework

# 带辅助进程
pip install xclaw-agentguard-framework[engine]
```

## 快速上手

### 基础用法

```python
from xclaw_agentguard import PromptInjectionDetector

# 创建检测器
detector = PromptInjectionDetector()

# 检测输入
result = detector.detect("用户输入内容")

if result.detected:
    print(f"发现威胁：{result.threat_level}")
    # 你的应用决定如何处理：阻断、记录、升级...
```

### 多个检测器组合

```python
from xclaw_agentguard import (
    PromptInjectionDetector,
    JailbreakDetector,
    CommandInjectionDetector
)

detectors = [
    PromptInjectionDetector(),
    JailbreakDetector(),
    CommandInjectionDetector(),
]

for detector in detectors:
    result = detector.detect(content)
    if result.detected:
        handle_threat(result)  # 你的处理逻辑
```

### 集成示例：保护 LLM 调用

```python
from xclaw_agentguard import PromptInjectionDetector

class SecureLLMClient:
    def __init__(self):
        self.detector = PromptInjectionDetector()
    
    def chat(self, user_input: str):
        # 先检测
        result = self.detector.detect(user_input)
        
        if result.detected and result.threat_level.value in ["high", "critical"]:
            return {
                "error": "检测到潜在安全威胁",
                "threat_level": result.threat_level.value
            }
        
        # 安全，继续处理
        return self.call_llm(user_input)
```

### 可选：辅助进程

辅助进程是便利层，不是必需的：

```bash
# 启动辅助进程
xclaw-agentguard engine-start
```

```python
from xclaw_agentguard.engine.interceptor import protect_openai

# 启用便利封装
protect_openai()

# 此后 OpenAI 调用自动经过检测
#（仅在辅助进程运行时有效）
```

**注意**：辅助进程没运行时，`protect_openai()` 会记录警告并透传到原始客户端。

## 12 个检测器

| 检测器 | 威胁类型 |
|--------|----------|
| `PromptInjectionDetector` | 提示注入 |
| `JailbreakDetector` | 越狱攻击 |
| `AgentHijackingDetector` | 智能体劫持 |
| `CommandInjectionDetector` | 命令注入 |
| `PathTraversalDetector` | 路径遍历 |
| `SQLInjectionDetector` | SQL 注入 |
| `BackdoorCodeDetector` | 后门代码 |
| `ExfiltrationGuard` | 数据外泄 |
| `OutputInjectionDetector` | 输出注入 |
| `SystemPromptLeakDetector` | 系统提示泄露 |
| `KnowledgePoisoningDetector` | 知识投毒 |
| `ContextManipulationDetector` | 上下文操控 |

直接导入使用：

```python
from xclaw_agentguard import PromptInjectionDetector, JailbreakDetector
```

## 自我保护（Anti-Jacked）

监控框架自身文件完整性，防御 CVE-2026-25253（ClawJacked）攻击——攻击者篡改智能体文件以绕过安全检测。

```bash
# 生成完整性基线
xclaw-agentguard baseline-generate

# 检查是否被篡改
xclaw-agentguard integrity-check

# 查看当前状态
xclaw-agentguard security-status
```

## 重要说明

### 检测 ≠ 防护

本框架**检测**潜在威胁，你的应用必须决定如何处理：

```python
result = detector.detect(input)

if result.detected:
    # 你决定：
    # - 阻断请求？
    # - 记录日志继续？
    # - 转人工审核？
    # - 加额外限制？
    handle_threat(result)  # 你的实现
```

### 安全没有万能钥匙

- 检测可能有误报、漏报
- 新型攻击可能绕过现有规则
- 安全是持久战，不是装个软件就万事大吉

## 系统要求

- Python 3.12.x
- 内存 512MB 起
- 磁盘约 50MB
- 可选：Docker（沙箱功能）

## 平台支持

| 平台 | 框架 | 辅助进程 |
|------|------|----------|
| macOS | ✅ | ✅ |
| Linux | ✅ | ✅ |
| Windows | ⚠️ 未测试 | ⚠️ 未测试 |

## 命令行工具

```bash
# 文件完整性管理
xclaw-agentguard baseline-generate   # 创建完整性基线
xclaw-agentguard integrity-check     # 验证文件完整性
xclaw-agentguard security-status     # 显示框架状态

# 辅助进程（可选）
xclaw-agentguard engine-start        # 启动辅助进程
xclaw-agentguard engine-stop         # 停止辅助进程
xclaw-agentguard engine-status       # 查看进程状态
```

## 文档

- [API 参考](docs/API.md) — 检测器详细文档
- [部署指南（英文）](docs/DEPLOYMENT.en.md) — 英文集成指南
- [部署指南（中文）](docs/DEPLOYMENT.zh.md) — 中文部署指南

## 许可证

MIT 许可证 — 详见 [LICENSE](LICENSE)

## 作者

XClaw AgentGuard Security Team

## 致谢

本项目受 [duru-memory](https://github.com/IanGYan/duru-memory) 启发。看到师兄开源的 OpenClaw skill，给了我们技术参考，也推动我们完善并开源 AgentGuard。感谢带路。

---

**免责声明**：本框架提供检测能力以辅助安全，不保证防护所有威胁。安全是一个过程，不是产品。请作为综合安全策略的一部分使用，包括代码审查、测试和监控。

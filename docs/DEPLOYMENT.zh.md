# XClaw AgentGuard Framework 部署指南

## 简介

XClaw AgentGuard 是一个 Python 安全检测库，为 AI 应用提供威胁识别能力。

**重要提示**：这是一个开发工具库，并非开箱即用的安全产品。需要开发者主动集成到业务代码中，由你的应用决定如何处理检测结果。

---

## 设计理念

### 库 vs 产品

| 本框架提供 | 本框架不提供 |
|-----------|------------|
| 检测工具，供代码调用 | 自动拦截所有请求 |
| 检测结果，供业务决策 | 代替你做安全决策 |
| 灵活集成，按需使用 | 无感知的透明保护 |
| 安全开发的辅助手段 | 完整的安全解决方案 |

### 两种使用方式

1. **框架模式**（推荐）：直接调用检测器，轻量无依赖
2. **辅助模式**（可选）：后台进程提供便捷封装，适合特定场景

---

## 安装

### 通过 OpenClaw 安装（推荐）

```bash
openclaw skills install https://github.com/neil-njcn/xclaw-agentguard-framework
```

### 通过 pip 安装

```bash
# 核心功能（12个检测器）
pip install xclaw-agentguard-framework

# 含辅助进程
pip install xclaw-agentguard-framework[engine]
```

---

## 框架模式（推荐）

### 快速开始

```python
from xclaw_agentguard import PromptInjectionDetector

# 初始化检测器
detector = PromptInjectionDetector()

# 检测输入
result = detector.detect("用户输入内容")

if result.detected:
    print(f"发现威胁: {result.threat_level}")
    # 由你的应用决定：阻断、记录、告警...
```

### 多检测器协同

```python
from xclaw_agentguard import (
    PromptInjectionDetector,
    JailbreakDetector,
    CommandInjectionDetector
)

def scan_input(text: str) -> dict:
    detectors = [
        PromptInjectionDetector(),
        JailbreakDetector(),
        CommandInjectionDetector(),
    ]
    
    threats = []
    for d in detectors:
        r = d.detect(text)
        if r.detected:
            threats.append({
                "type": d.__class__.__name__,
                "level": r.threat_level.value,
                "confidence": r.confidence
            })
    
    return {"safe": len(threats) == 0, "threats": threats}
```

### 集成示例：保护 LLM 调用

```python
from xclaw_agentguard import PromptInjectionDetector

class SecureLLM:
    def __init__(self):
        self.guard = PromptInjectionDetector()
    
    def chat(self, user_input: str):
        result = self.guard.detect(user_input)
        
        if result.detected and result.threat_level.value in ["high", "critical"]:
            return {"error": "输入存在安全风险", "level": result.threat_level.value}
        
        return self.call_llm(user_input)
```

---

## 辅助模式（可选）

需额外安装 `[engine]` 依赖，提供便捷封装。

```bash
# 安装含辅助进程的版本
pip install xclaw-agentguard-framework[engine]

# 启动辅助进程（前台）
xclaw-agentguard engine-start

# 后台运行
xclaw-agentguard engine-start --daemon
```

### 使用拦截器

```python
from xclaw_agentguard.engine.interceptor import protect_openai

protect_openai()  # OpenAI 调用自动经过检测
```

**注意**：辅助进程未运行时，会静默回退到原生客户端，不会报错。

---

## 文件完整性保护（Anti-Jacked）

防御 CVE-2026-25253（ClawJacked）攻击——检测框架文件是否被恶意篡改以绕过安全检测。

```bash
# 生成完整性基线
xclaw-agentguard baseline-generate

# 检查文件完整性
xclaw-agentguard integrity-check

# 查看安全状态
xclaw-agentguard security-status
```

---

## 检测器清单（12个）

| 检测器 | 检测目标 |
|-------|---------|
| `PromptInjectionDetector` | 提示注入攻击（如 "忽略先前指令"） |
| `JailbreakDetector` | 越狱攻击（如 DAN、开发者模式） |
| `AgentHijackingDetector` | 代理劫持（工具滥用、权限提升） |
| `CommandInjectionDetector` | 命令注入（Shell 注入攻击） |
| `PathTraversalDetector` | 路径遍历（如 `../../etc/passwd`） |
| `SQLInjectionDetector` | SQL 注入攻击 |
| `BackdoorCodeDetector` | 后门代码植入 |
| `ExfiltrationGuard` | 敏感数据外泄（API 密钥、密码） |
| `OutputInjectionDetector` | 输出内容篡改（钓鱼、恶意链接） |
| `SystemPromptLeakDetector` | 系统提示窃取攻击 |
| `KnowledgePoisoningDetector` | 知识库投毒（虚假事实注入） |
| `ContextManipulationDetector` | 上下文篡改（记忆操控） |

**导入方式**：
```python
from xclaw_agentguard import PromptInjectionDetector, JailbreakDetector
# 或全部导入
from xclaw_agentguard import *
```

---

## 环境要求

| 项目 | 要求 |
|-----|------|
| Python | 3.12.x |
| 内存 | 512MB 起 |
| 磁盘 | 约 50MB |
| 可选 | Docker（沙箱功能）|

---

## 配置说明

框架模式**零配置**即可使用。检测器内置默认参数，开箱即用。

如需调整，可通过环境变量：

```bash
export AGENTGUARD_LOG_LEVEL=INFO
export AGENTGUARD_SOCKET=/tmp/xclaw_agentguard.sock
```

---

## 常见问题

**Q: 导入报错？**
```bash
pip list | grep xclaw-agentguard-framework  # 确认已安装
```

**Q: 辅助进程启动失败？**
```bash
pip install xclaw-agentguard-framework[engine]  # 检查依赖
ls -la /tmp/  # 检查目录权限
```

**Q: 检测异常？**
```python
result = detector.detect(str(user_input))  # 确保输入为字符串
```

---

## 核心理念

### 检测 ≠ 防护

本框架负责**发现**威胁，**处置**权在你：

```python
result = detector.detect(input)

if result.detected:
    # 你可以选择：
    # - 阻断请求
    # - 记录日志并放行
    # - 人工审核
    # - 降级处理
    handle(result)  # 你的业务逻辑
```

### 安全没有万能钥匙

- 检测难免有误报、漏报
- 新攻击手段层出不穷
- 安全是持久战，不是装个软件就万事大吉

---

## 功能速查

| 功能 | 需配置 | 需辅助进程 |
|-----|-------|-----------|
| 基础检测 | 否 | 否 |
| 多检测器组合 | 否 | 否 |
| 文件完整性监控 | 需初始化基线 | 否 |
| OpenAI 便捷封装 | 否 | 是 |

**最简用法**：`pip install` 后直接 `import`，无需任何配置。

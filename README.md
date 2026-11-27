# 查表生成器 · Syscall & Shellcraft

面向 CTF / PWN 学习的 Linux 系统调用查表与代码生成工具。选架构、查调用、填参数，把调用号、寄存器、shellcraft 调用链和 ROP 模板放在同一页对照。

**[在线使用](https://wzeze-lll.github.io/syscall-shellcraft-generator/)** · [查看源码](index.html) · [配套 CTF 题解](https://github.com/wzeze-lll/CTF-Writeups)

纯静态单页，使用 HTML、CSS 和原生 JavaScript 编写。下载后直接用浏览器打开 `index.html` 即可离线使用，无需安装依赖或配置服务。

## 功能一览

| 功能 | 使用方式 | 页面提供的结果 |
| --- | --- | --- |
| 系统调用查表 | 选择 amd64 / i386，搜索调用名或调用号 | 调用号、参数签名与寄存器对应关系 |
| shellcraft 代码生成 | 按参数提示填值 | `shellcraft.<arch>.linux.syscall(...)` 代码骨架，支持字符串压栈 |
| 多步调用链 | 添加单个调用，或选择内置示例 | 串联多步代码，显示返回值去向及被覆盖的提醒 |
| seccomp 辅助检查 | 手动填写允许的调用号或名称，以及可选参数限制 | 名单外调用标红、部分参数限制标黄，支持按名单生成链骨架 |
| ROP 模板 | 选择模板，填写 offset、BSS 和 gadget 地址 | pwntools `flat()` 链骨架、NUL 字节提示与核对清单 |
| 填空练习 | 在 amd64 练习区填写寄存器与调用参数 | 对照检查与错误提示 |
| 常量速查 | 查看 fd、PROT、MAP、open flags、mode 等 | 点击常量填入上一个选中的参数框 |

## 快速开始

1. 先选架构：`amd64 · syscall` 或 `i386 · int 0x80`。
2. 输入 `read`、`write`、`mmap` 等名称，或对应架构的调用号。
3. 对照参数签名与寄存器说明填值；地址、大小和文件描述符取自自己的目标程序。
4. 查看实时生成的代码；需要组合多步时，点击“＋ 加到链里”。
5. 把代码放入对应架构的 pwntools 环境，在本地题目中检查实际返回值、内存与收发过程。

```text
选架构 → 搜调用 → 看参数与寄存器 → 填值
                                      ↓
                     生成单步代码 / 加入调用链
                                      ↓
                      在目标环境汇编、调试和验证
```

页面生成代码文本；使用生成结果进行汇编或运行时，仍需在自己的 Python 环境中使用 pwntools。

## 调用链与白名单

内置 `open → read → write` 和 `open → mmap → write` 示例，便于观察 fd、缓冲区地址、长度与返回值如何传递。

在“seccomp 白名单检查”中填写调用名称或调用号，用逗号或空格分隔；也可以选择预设，再点击“按白名单直接生成工具链”。切换架构后，应按新架构重新确认调用号和参数。

这里检查的是**手动输入的条件**。页面没有读取或执行目标程序的 seccomp BPF；生成链在真实程序中能否执行，还取决于规则、参数、调用结果和内存状态。未设置名单时，页面跳过这项检查。

## ROP 模板

| 模板 | 架构 | 链的用途 |
| --- | --- | --- |
| 4.1 | i386 | `read` 读到 BSS，再调用 `execve` |
| 4.2 | i386 | 用写内存 gadget 放入 `/bin/sh`，再调用 `execve` |
| 4.3 | amd64 | 使用 `syscall` 的 `execve` 链 |
| 4.1a | amd64 | `read → BSS → execve` 的 amd64 版本 |
| 4.2a | amd64 | 写入 `/bin/sh → execve` 的 amd64 版本 |

填写输入到返回地址的 offset、可写地址和对应 gadget 后，页面按模板生成代码。支持组合 pop 与单 pop 的选择，并提供两阶段发送延迟、NUL 字节数量提示和核对清单。

示例地址和 `0` 占位值需要按当前 ELF 替换。4.2 中保留的示例 gadget 地址未获动态验证；生成结果按 **STATIC_ONLY** 使用，不能据此认定已在某道题目中跑通。

## 架构与数据范围

- 当前覆盖 Linux amd64 与 i386；调用号和参数寄存器按架构分开处理。
- 查表数据与参数提示内置在页面中；新增调用、旧 ABI 与特定内核配置仍应对照目标系统核验。
- 部分无实现、返回 `ENOSYS` 的调用已剔除或标注，具体范围见页面中的表注。
- `clone` 等调用有架构差异；裸系统调用的参数顺序也可能与 libc 包装函数不同，填写前查看参数说明。
- 字符串指针、结构体、数组和运行时返回地址需要结合程序准备；自动填充与提示不能代替目标环境检查。

## 文件结构

```text
syscall-shellcraft-generator/
├── index.html   # 界面、调用表、参数提示与代码生成逻辑
└── README.md    # 项目介绍与使用说明
```

## 对照资料

- [Linux x86-64 系统调用号表](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
- [Linux i386 系统调用号表](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl)
- [Linux man-pages：syscall(2)](https://man7.org/linux/man-pages/man2/syscall.2.html)
- [pwntools：shellcraft 文档](https://docs.pwntools.com/en/stable/shellcraft.html)

结合具体题目阅读与复盘，可查看 [CTF-Writeups](https://github.com/wzeze-lll/CTF-Writeups) 中的逆向、栈、堆和内核题目。

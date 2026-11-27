# PWN 脚本工作台 · 查表生成器

面向 CTF / PWN 学习的脚本工作台。根据已有函数与输入条件选择打法，填写实测偏移、符号和地址，生成可单独保存的 pwntools 脚本；同页保留系统调用查表、shellcraft 调用链与寄存器参考。

**[在线使用](https://wzeze-lll.github.io/syscall-shellcraft-generator/)** · [查看源码](index.html) · [配套 CTF 题解](https://github.com/wzeze-lll/CTF-Writeups)

纯静态网页，使用 **TypeScript + HTML + CSS** 编写，启用 TypeScript 严格类型检查。浏览器运行仓库内已编译的 `app.js`，无需后端服务或运行时依赖。

在线直接打开上方链接；离线使用时下载整个仓库并解压，再打开 `index.html`。请保留同目录下的 `app.js` 和 `style.css`，仅下载 HTML 文件无法加载完整功能。

## 功能一览

| 功能 | 使用方式 | 页面提供的结果 |
| --- | --- | --- |
| 完整 EXP 生成 | 选择 6 类模板，填写目标条件 | 独立的启动、载荷、收发与交互脚本，可复制或下载 `.py` |
| 函数线索识别 | 粘贴 C 函数或反编译伪代码 | 识别常见函数调用并建议模板；不推算偏移、不判断可利用性 |
| 系统调用查表 | 选择 amd64 / i386，搜索调用名或调用号 | 调用号、参数签名与寄存器对应关系 |
| shellcraft 代码生成 | 按参数提示填值 | `shellcraft.<arch>.linux.syscall(...)` 代码骨架，支持字符串压栈 |
| 多步调用链 | 添加单个调用，或选择内置示例 | 串联多步代码，显示返回值去向及被覆盖的提醒 |
| seccomp 辅助检查 | 手动填写允许的调用号或名称，以及可选参数限制 | 名单外调用标红、部分参数限制标黄，支持按名单生成链骨架 |
| ROP 模板 | 选择模板，填写 offset、BSS 和 gadget 地址 | pwntools `flat()` 链骨架、NUL 字节提示与核对清单 |
| 填空练习 | 在 amd64 练习区填写寄存器与调用参数 | 对照检查与错误提示 |
| 常量速查 | 查看 fd、PROT、MAP、open flags、mode 等 | 点击常量填入上一个选中的参数框 |

页面提供分区导航；桌面上并排显示参数与代码，手机上自动改为单列。参数说明、架构差异与模板步骤可按需展开，右上角可切换浅色 / 深色配色。

## 快速开始

### 从函数生成 EXP

1. 在 **EXP 脚本** 中选择打法，或展开“粘贴函数，辅助选型”。“用当前样例试一下”提供对应的示例函数或指令。
2. 填写附件路径、架构、用 cyclic + GDB 测出的返回地址偏移、输入提示符与发送方式。
3. 填写模板参数，例如 `win` 函数名，或目标配套的 libc、泄漏符号和返回入口。PIE 基址、loader 与栈对齐在展开项中设置。
4. 查看载荷组成和完整代码，复制或下载脚本，在目标 Linux 环境中运行与调试。

```bash
python3 exploit_win.py
python3 exploit_win.py REMOTE HOST=127.0.0.1 PORT=1337  # 示例连接参数，按题目修改
```

| EXP 模板 | 架构 | 需要确认的条件 |
| --- | --- | --- |
| ret2win / ret2text | amd64、i386 | 已有目标函数，能控制返回地址；可填函数参数 |
| ret2plt | amd64、i386 | 已导入 system，目标内存存在命令字符串 |
| ret2libc / puts | amd64、i386 | GOT 已解析、匹配 libc、可重入输入、明确泄漏结束标记与有效字节数 |
| ret2libc / write | amd64、i386 | 可设置 write 三个参数，定长接收一个指针，再生成第二阶段 |
| ret2csu | amd64 | 核对两段指令与两种寄存器布局；生成一次间接调用及返回入口 |
| SROP | amd64 | 独立 pop rax/ret、syscall/ret、已有 /bin/sh、已知可用栈；单帧 execve |

模板结合本地 ROP 笔记中的 ret2text、ret2libc、ret2csu 与 SROP 整理。每份脚本包含所需函数，不依赖其他模板拼接。CSU 模板只完成一次调用；SROP 不涵盖带 `leave` 副作用或两帧方案。

函数识别在浏览器本地按文本规则完成，不上传输入，也不执行粘贴内容。数组长度不能代替返回地址偏移；识别到 `system` 不代表一定存在可用的 PLT。缺失偏移、PIE 基址、Canary 处理或关键地址时，脚本会明确停止。`puts` 的地址字节遇 NUL 或分隔符可能截断，边界不可靠时应考虑 `write` 定长泄漏。

### 查系统调用与生成 shellcraft

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

在“seccomp 白名单检查”中填写调用名称或调用号，用逗号或空格分隔；也可以选择预设，再点击“生成允许的调用链”。切换架构后，应按新架构重新确认调用号和参数。

这里检查的是**手动输入的条件**。页面没有读取或执行目标程序的 seccomp BPF；生成链在真实程序中能否执行，还取决于规则、参数、调用结果和内存状态。未设置名单时，页面跳过这项检查。

## ROP 模板

| 模板 | 架构 | 链的用途 |
| --- | --- | --- |
| 4.1 | i386 | `read` 读到 BSS，再调用 `execve` |
| 4.2 | i386 | 用写内存 gadget 放入 `/bin/sh`，再调用 `execve` |
| 4.3 | amd64 | 使用 `syscall` 的 `execve` 链 |
| 4.1a | amd64 | `read → BSS → execve` 的 amd64 版本 |
| 4.2a | amd64 | 写入 `/bin/sh → execve` 的 amd64 版本 |

填写输入到返回地址的 offset、可写地址和对应 gadget 后，页面按模板生成代码。支持组合 pop 与单 pop 的选择，并提供两阶段可选延时、NUL 字节数量提示和核对清单。gets 与 strcpy 分别选择：gets 按换行结束，生成时补换行并检查载荷中的换行字节；strcpy 按 NUL 终止。单次 read 可能短读，延时不能代替协议同步。字符串按 UTF-8 编码后分块。

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
├── index.html          # 页面结构
├── style.css           # 页面样式
├── app.ts              # TypeScript 源码：调用表、提示、查找与生成逻辑
├── exp.ts              # 独立 EXP 模板、函数线索识别与表单
├── app.js              # tsc 编译产物，供浏览器和 GitHub Pages 直接加载
├── tsconfig.json       # strict 类型检查与编译设置
├── package.json        # 开发命令与固定版本的 TypeScript 依赖
├── package-lock.json   # 锁定开发依赖
├── generator.test.cjs  # 生成逻辑与页面资源回归检查
└── README.md
```

## 开发检查

开发需要 Node.js 18+、npm 和 Python 3；日常使用网页无需安装这些工具。

```bash
npm ci                 # 首次开发时安装锁定的编译器
npm run typecheck      # TypeScript 严格类型检查，不生成文件
npm run build          # 将 exp.ts 和 app.ts 编译成 app.js
npm test               # 重新编译并运行回归检查
```

修改逻辑时编辑 `exp.ts` / `app.ts`，运行构建后一起提交源码与 `app.js`；请勿直接修改编译产物。`index.html` 使用普通 script 加载 `app.js`，支持本地 file:// 打开；GitHub Pages 直接发布根目录，无需在线编译。

新增 EXP 检查覆盖 30 种模板/架构/发送方式组合、参数校验和函数识别。若 Python 环境已有 pwntools，还会检查 CSU 的两种布局与 SROP 帧的实际打包字节；没有 pwntools 时该组明确标记为跳过。测试不会启动题目进程，不能替代对实际 ELF、libc 和运行协议的验证。

检查覆盖 UTF-8 分块、输入终止条件提示、十六进制精确查找、五种 ROP 模板在不同输入方式下的 Python 语法与发送方式，以及部分核心 ABI 映射。另外检查页面引用的资源是否存在、默认 write 是否能初始化，以及预设调用链在两种架构下是否能生成。测试在最小 DOM 替身中运行编译后的生成逻辑，并不启动题目进程，也不代表真实题目利用通过。

## 对照资料

- [Linux x86-64 系统调用号表](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
- [Linux i386 系统调用号表](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_32.tbl)
- [Linux man-pages：syscall(2)](https://man7.org/linux/man-pages/man2/syscall.2.html)
- [pwntools：shellcraft 文档](https://docs.pwntools.com/en/stable/shellcraft.html)
- [pwntools：ROP 构造](https://docs.pwntools.com/en/stable/rop/rop.html)、[SROP 帧](https://docs.pwntools.com/en/stable/rop/srop.html)、[收发接口](https://docs.pwntools.com/en/stable/tubes.html)

结合具体题目阅读与复盘，可查看 [CTF-Writeups](https://github.com/wzeze-lll/CTF-Writeups) 中的逆向、栈、堆和内核题目。

输入行为对照：[gets(3)](https://man7.org/linux/man-pages/man3/gets.3.html)、[strcpy(3)](https://man7.org/linux/man-pages/man3/strcpy.3.html)、[read(2)](https://man7.org/linux/man-pages/man2/read.2.html)。

TypeScript 迁移与编译设置参考：[官方迁移指南](https://www.typescriptlang.org/docs/handbook/migrating-from-javascript.html)、[strict 配置](https://www.typescriptlang.org/tsconfig/strict.html)。

# syscall-shellcraft-generator

Linux 系统调用查表与 shellcraft 生成器（静态单页）。在线用：https://wzeze-lll.github.io/syscall-shellcraft-generator/ ；也可以直接打开 `index.html`，无需安装、无需联网。

## 这是干什么的

写 PWN 的 exp 时，查系统调用号、记参数顺序和走哪个寄存器、拼 shellcraft 调用链、拼 ROP 链，都要翻 man、翻表、翻笔记。这个页面把这些事收到一处：选架构 → 搜调用 → 按提示填参数 → 直接生成能粘进 exp 的 pwntools 代码，seccomp 白名单检查和 ROP 链模板也在同一页。

## 功能

- **查表**：amd64 / i386 系统调用表，按名字或调用号搜索，显示调用号、参数顺序与寄存器。amd64 表 369 条；i386 字面 380 条、去重后有效 410 条。有名无实现、调用只返回 `-ENOSYS` 的号已标注或剔除（amd64 17 个；i386 的 149 `_sysctl`、253 `lookup_dcookie` 已剔除）。
- **生成 shellcraft**：按参数填值，实时生成 `shellcraft.<arch>.linux.syscall(...)` 代码，可拼多步调用链（自动带上一步的 fd / buf / count；字符串参数自动生成 pushstr）。
- **seccomp 白名单检查**：填放行调用号，生成时标出不在名单里的调用；支持一键生成白名单内的整条链（open → mmap → write、open → read → write）。
- **ROP 链模式**：i386 `int 0x80` 的 read → BSS → execve（4.1）、写 `/bin/sh` 到 BSS 再 execve（4.2），amd64 `syscall` execve（4.3），另有 amd64 的 4.1a / 4.2a 变体。按 gadget 地址与 offset 生成 pwntools 代码，带 `\x00` 数量警告、两次发送可调延迟（默认 0.3s）、单 pop 回退方案和 12 项核对清单。4.2 示例 gadget 地址由用户提供、未验证；4.3 与 4.1a / 4.2a 的地址全是 0 占位，按目标重测后填。
- **练习与常量速查**：填空练习、常用常量（PROT / MAP 标志等）。

## 使用

浏览器打开在线地址或本地 `index.html` 即可。先选架构（amd64 / i386），搜调用名或调用号，照提示把参数填进框里，生成的代码复制到 exp 里用。

## 说明

- 调用号对照内核 `unistd_64.h` / `unistd_32.h` 与 `syscall_64.tbl` / `syscall_32.tbl` 核对。
- clone 的裸系统调用参数顺序：amd64 为 `flags, stack, parent_tid, child_tid, tls`；i386 为 `flags, stack, parent_tid, tls, child_tid`（与 glibc 包装函数顺序不同）。
- 生成的代码为静态模板，需按目标程序的 gadget 地址、offset、BSS 地址填参，并在虚拟机里实测通过才算可用；页面本身未经 VM 真题全量验证。

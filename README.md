# syscall-shellcraft-generator

Linux 系统调用查表与 shellcraft 生成器（静态单页，打开 `index.html` 即用）。

## 功能

- **查表**：amd64 / i386 系统调用表，按名字或调用号搜索，显示调用号、参数顺序与寄存器。
- **生成 shellcraft**：按参数填值，实时生成 `shellcraft.<arch>.linux.syscall(...)` 代码，可拼多步调用链（自动带上一步的 fd / buf / count）。
- **seccomp 白名单检查**：填放行调用号，生成时标出不在名单里的调用；支持一键生成白名单内的整条链（open → mmap → write、open → read → write）。
- **ROP 链模式**：i386 `int 0x80` 的 read → BSS → execve、写 `/bin/sh` 到 BSS 再 execve，amd64 `syscall` execve 三种模板，按 gadget 地址与 offset 生成 pwntools 代码。
- **练习与常量速查**：填空练习、常用常量（PROT / MAP 标志等）。

## 使用

直接用浏览器打开 `index.html`，无需安装、无需联网。

## 说明

- 调用号对照内核 `unistd_64.h` / `unistd_32.h` 核对；i386 表含 0–423 段（含 time64 调用）。
- clone 的裸系统调用参数顺序：amd64 为 `flags, stack, parent_tid, child_tid, tls`；i386 为 `flags, stack, parent_tid, tls, child_tid`（与 glibc 包装函数顺序不同）。
- 生成的代码为静态模板，需按目标程序的 gadget 地址、offset、BSS 地址填参，并在虚拟机里实测通过才算可用。

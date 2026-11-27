const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
function load(script = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), initialize = false) {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, { value: '', textContent: '', innerHTML: '', style: {}, hidden: false,
      classList: { add(){}, remove(){}, toggle(){} },
      addEventListener(type, fn){ (this._listeners || (this._listeners = {}))[type] = fn; },
      querySelectorAll(){ return []; }, scrollIntoView(){} });
    return nodes.get(id);
  }
  for (const tag of html.matchAll(/<input\b[^>]*>/g)) {
    const id = /\bid="([^"]+)"/.exec(tag[0]);
    const value = /\bvalue="([^"]*)"/.exec(tag[0]);
    if (id) node(id[1]).value = value ? value[1] : '';
  }
  const c = { TextEncoder, document: { getElementById: node, querySelectorAll(){return [];}, addEventListener(){} },
    navigator: {}, setTimeout(){}, console };
  vm.createContext(c);
  vm.runInContext(initialize ? script : script.replace(/selectByName\("write"\);\s*$/, ''), c);
  c.EXP_RECIPES = vm.runInContext("EXP_RECIPES", c);
  c.node = node;
  return c;
}
test('ROP string chunks preserve UTF-8 bytes and padding', () => {
  const c=load();
  for (const size of [4,8]) {
    const data=Buffer.from(c.ropChunkBytes('/tmp/测试',size).flat());
    const expected=Buffer.from('/tmp/测试\0');
    assert.equal(data.length % size,0);
    assert.deepEqual(data.subarray(0,expected.length),expected);
    assert.ok(data.subarray(expected.length).every(x=>x===0));
  }
});
test('gets and strcpy have separate terminator guidance', () => {
  const c=load();
  assert.doesNotMatch(c.ropWarnFor(3,80,'gets'), /第一个.*截断/);
  assert.match(c.ropWarnFor(3,80,'gets'), /换行/);
  assert.match(c.ropWarnFor(3,80,'strcpy'), /NUL.*终止/);
});
test('hexadecimal exact lookup selects the same syscall as decimal', () => {
  const c=load();
  assert.equal(c.findExactSys('0x1').name,'write');
  assert.equal(c.findExactSys('1').name,'write');
  c.SYS=c.SYS32;
  assert.equal(c.findExactSys('0x4').name,'write');
});
test('ROP templates generate Python syntax and gets sends a terminating newline', () => {
  const c=load();
  for (const prim of ['unknown','gets','strcpy','read-fixed','read-stream']) {
    c.ropPrim=prim; c.node('rop42Str').value='/tmp/测试';
    for (const tpl of ['41','42','43','41a','42a']) {
      c.ropTpl=tpl; c.ropGen();
      const code=c.node('ropCode').textContent;
      const parsed=spawnSync('python3',['-c','import ast,sys;ast.parse(sys.stdin.read())'],{input:code,encoding:'utf8'});
      assert.equal(parsed.status,0,`${prim}/${tpl}: ${parsed.stderr}`);
      if (prim==='gets' && ['41','41a','43'].includes(tpl)) assert.match(code,/io\.sendline\(chain\)/);
      if (prim!=='gets' && ['41','41a','43'].includes(tpl)) assert.match(code,/io\.send\(chain\)/);
    }
  }
});
test('lookup tables contain unique numbers and core ABI mappings', () => {
  const c=load();
  for (const [table,read,write,execve] of [[c.SYS64,0,1,59],[c.SYS32,3,4,11]]) {
    assert.equal(new Set(table.map(s=>s.nr)).size,table.length);
    for (const [name,nr] of [['read',read],['write',write],['execve',execve]]) assert.equal(table.find(s=>s.name===name).nr,nr);
  }
  assert.equal(c.SYS32.find(s=>s.nr===90).args.length,1);
  assert.equal(c.SYS32.find(s=>s.name==='mmap2').args.length,6);
});

test('ROP step text displays angle brackets instead of parsing HTML', () => {
  const c=load(); c.ropTpl='42'; c.node('rop42Str').value='<tag>';
  c.ropGen();
  assert.doesNotMatch(c.node('ropSteps').innerHTML, /<tag>/);
  assert.match(c.node('ropSteps').innerHTML, /&lt;/);
});

test('static entry point loads local compiled assets and initializes write', () => {
  assert.match(html, /<script src="app\.js"><\/script>/);
  assert.match(html, /<link rel="stylesheet" href="style\.css">/);
  assert.doesNotMatch(html, /<script>/);
  assert.ok(fs.statSync(path.join(__dirname, 'style.css')).size > 0);
  const c = load(undefined, true);
  assert.equal(c.cur.name, 'write');
  assert.equal(c.node('q').value, 'write');
});
test('chain presets use the active architecture', () => {
  const c=load();
  for(const arch of ['amd64','i386']) {
    c.arch=arch; c.SYS=c[arch==='amd64'?'SYS64':'SYS32'];
    c.preset([['read',['0',"'rsp'",'0x100']],['write',['1',"'rsp'",'0x100']]]);
    assert.deepEqual(Array.from(c.chain,s=>s.nr),arch==='amd64'?[0,1]:[3,4]);
    assert.match(c.node('chainCode').textContent,new RegExp('shellcraft\\.'+arch+'\\.linux'));
    assert.throws(()=>c.requireSys('not_a_syscall'),/Syscall unavailable/);
  }
});

function expFixture(c, kind, arch='amd64') {
  const v = {binary:'./pwn',arch,offset:'40',mode:'raw',prompt:'Input:\\n',base:'',
    loader:'',align1:'0',align2:'0'};
  for(const field of c.EXP_RECIPES[kind].fields) v[field.key]=field.value;
  if(kind==='csu') Object.assign(v,{csuPop:'0x401100',csuCall:'0x401120'});
  if(kind==='srop') Object.assign(v,{popRax:'0x401100',syscall:'0x401120',stringAddress:'0x402000',stackAddress:'0x405000'});
  return v;
}
test('new EXP recipes emit independent Python scripts across architectures and transports', () => {
  const c=load();
  let combinations=0;
  for(const kind of Object.keys(c.EXP_RECIPES)) for(const arch of ['amd64','i386']) {
    if(arch==='i386' && c.EXP_RECIPES[kind].amd64Only) continue;
    for(const mode of ['raw','line','cstring']) {
      const v={...expFixture(c,kind,arch),mode,binary:"./题目 'demo'.elf"};
      const code=c.generateExp(kind,v);
      const parsed=spawnSync('python3',['-c','import ast,sys;ast.parse(sys.stdin.read())'],{input:code,encoding:'utf8'});
      assert.equal(parsed.status,0,kind+'/'+arch+'/'+mode+': '+parsed.stderr);
      for(const part of ['def start():','def send_payload(io, payload):','def main():',"if __name__ == '__main__':",'io.interactive()']) assert.ok(code.includes(part),part);
      assert.doesNotMatch(code,/raw\.strip\(/);
      combinations++;
    }
  }
  assert.equal(combinations,30);
});
test('EXP fields reject ambiguous or invalid values and keep byte escapes exact', () => {
  const c=load();
  assert.equal(c.expNumber('040','offset'),'40');
  assert.equal(c.expExpression('0005','arg'),'5');
  assert.equal(c.expExpression('0xdeadbeefdeadbeef','arg'),'0xdeadbeefdeadbeef');
  assert.equal(c.expBytes('Input:\\n'),"b'Input:\\x0a'");
  assert.throws(()=>c.expNumber('0','address',true),/不能用 0/);
  assert.throws(()=>c.generateExp('win',{...expFixture(c,'win'),offset:'32+8'}),/整数/);
  assert.throws(()=>c.generateExp('win',{...expFixture(c,'win'),arguments:'__import__("os")'}),/仅支持/);
  assert.throws(()=>c.generateExp('srop',expFixture(c,'srop','i386')),/仅支持 amd64/);
  assert.throws(()=>c.expBytes('\\q'),/仅支持/);
  assert.throws(()=>c.generateExp('libc-puts',{...expFixture(c,'libc-puts'),leakEnd:''}),/不能为空/);
});
test('function clues choose a recipe without inventing an offset', () => {
  const c=load();
  const win=c.expAnalyzeSource('void shell(){system("/bin/sh");} void vuln(){char b[32];gets(b);}');
  assert.equal(win.kind,'win');assert.equal(win.target,'shell');
  assert.ok(win.calls.includes('gets'));assert.equal(win.offset,undefined);
  assert.equal(c.expAnalyzeSource('int main(){write(1,b,8);read(0,b,200);}').kind,'libc-write');
  assert.equal(c.expAnalyzeSource('int main(){read(0,b,200);}').kind,null);
});
const hasPwntools=spawnSync('python3',['-c','import pwn'],{encoding:'utf8'}).status===0;
test('CSU layouts and SROP frames pack using real pwntools without starting a process',
  {skip:!hasPwntools && 'optional: install pwntools for binary packing checks'}, () => {
  const c=load();
  const configs=[];
  for(const layout of ['reverse','forward']) configs.push({
    kind:'csu',code:c.generateExp('csu',{...expFixture(c,'csu'),csuLayout:layout})
  });
  configs.push({kind:'srop',code:c.generateExp('srop',expFixture(c,'srop'))});
  const program="\nimport ast,json,sys\nfrom pwn import context,flat,u64\nitems=json.load(sys.stdin)\nfor item in items:\n    tree=ast.parse(item['code'])\n    functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}\n    context.clear(arch='amd64',os='linux')\n    env={'flat':flat,'CSU_POP':0x401100,'CSU_CALL':0x401120,'CSU_LAYOUT':'reverse','OFFSET':40}\n    if item['kind']=='csu':\n        env['CSU_LAYOUT']='forward' if 'CSU_LAYOUT = \"forward\"' in item['code'] else 'reverse'\n        fn=functions['csu_call']\n        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'generated','exec'),env)\n        raw=env['csu_call'](0x404000,1,0x404010,8,0x401050)\n        words=[u64(raw[i:i+8]) for i in range(0,len(raw),8)]\n        assert len(words)==16\n        assert words[:4]==[0x401100,0,1,0x404000]\n        assert words[4:7]==([1,0x404010,8] if env['CSU_LAYOUT']=='forward' else [8,0x404010,1])\n        assert words[7]==0x401120 and words[8:15]==[0]*7 and words[15]==0x401050\n        try:env['csu_call'](0x404000,0x100000000,2,3,4)\n        except ValueError:pass\n        else:raise AssertionError('CSU must reject truncated arg1')\n    else:\n        from pwn import SigreturnFrame,constants\n        env.update(SigreturnFrame=SigreturnFrame,constants=constants,POP_RAX=0x401100,\n                   SYSCALL=0x401120,BINSH=0x402000,STACK_ADDRESS=0x405000)\n        fn=functions['build_payload']\n        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'generated','exec'),env)\n        raw=env['build_payload']()\n        assert raw[:40]==b'A'*40\n        assert [u64(raw[i:i+8]) for i in range(40,64,8)]==[0x401100,15,0x401120]\n        frame=raw[64:]\n        assert len(frame)==248\n        for offset,value in [(104,0x402000),(112,0),(136,0),(144,59),(160,0x405000),(168,0x401120)]:\n            assert u64(frame[offset:offset+8])==value,(offset,value)\nprint('CSU layouts and SROP bytes passed; no target process started.')\n";
  const result=spawnSync('python3',['-c',program],{input:JSON.stringify(configs),encoding:'utf8'});
  assert.equal(result.status,0,result.stdout+'\n'+result.stderr);
});

test('generated receive and send functions preserve boundaries and reject short reads', () => {
  const c=load();
  const scripts=['libc-puts','libc-write'].map(kind=>({kind,code:c.generateExp(kind,expFixture(c,kind))}));
  const program=String.raw`
import ast,json,sys
class Tube:
    def __init__(self, data=b''): self.data=data; self.sent=[]
    def recvuntil(self, marker):
        i=self.data.find(marker)
        if i<0:return b''
        result,self.data=self.data[:i+len(marker)],self.data[i+len(marker):]
        return result
    def recvn(self,n):
        result,self.data=self.data[:n],self.data[n:]
        return result
    def unrecv(self,b):self.data=b+self.data
    def send(self,b):self.sent.append(b)
    def sendline(self,b):self.sent.append(b+b'\n')
def fails(error,fn):
    try:fn()
    except error:return
    raise AssertionError('expected '+error.__name__)
for item in json.load(sys.stdin):
    tree=ast.parse(item['code'])
    funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('receive_leak','send_payload')]
    env=dict(LEAK_PREFIX=b'prefix',LEAK_END=b'\n',LEAK_BYTES=6,POINTER_SIZE=8,
             PROMPT=b'Input:',INPUT_MODE='raw',unpack=lambda b,word_size:int.from_bytes(b,'little'))
    exec(compile(ast.Module(body=funcs,type_ignores=[]),'generated','exec'),env)
    receive,send=env['receive_leak'],env['send_payload']
    raw=b' \x11\x22\x33\x44\x7f' if item['kind']=='libc-puts' else b'\x00\x0a\x20\x33\x44\x7f\x00\x00'
    tail=b'\n' if item['kind']=='libc-puts' else b''
    tube=Tube(b'prefix'+raw+tail+b'Input:')
    assert receive(tube)==int.from_bytes(raw,'little')
    send(tube,b'AB');assert tube.sent==[b'AB']
    fails(TimeoutError,lambda:receive(Tube(b'')))
    fails(TimeoutError if item['kind']=='libc-write' else ValueError,lambda:receive(Tube(b'prefixA'+tail)))
    fails(TimeoutError,lambda:send(Tube(),b'AB'))
    env['PROMPT']=b'';env['INPUT_MODE']='line'
    fails(ValueError,lambda:send(Tube(),b'A\nB'))
    tube=Tube();send(tube,b'AB');assert tube.sent==[b'AB\n']
    env['INPUT_MODE']='cstring';fails(ValueError,lambda:send(Tube(),b'A\0B'))
    if item['kind']=='libc-puts':
        env['LEAK_END']=env['PROMPT']=b'Input:'
        tube=Tube(b'prefix'+raw+b'Input:')
        assert receive(tube)==int.from_bytes(raw,'little')
        assert tube.data==b'Input:'
        send(tube,b'AB');assert tube.sent==[b'AB']
print('receive/send boundary checks passed')
`;
  const result=spawnSync('python3',['-c',program],{input:JSON.stringify(scripts),encoding:'utf8'});
  assert.equal(result.status,0,result.stdout+'\n'+result.stderr);
});

test('ELF profile import exists in the built app.js and round-trips', () => {
  const src = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
  for (const name of ['parseElfProfile', 'applyElfProfile', 'expProfileApply']) assert.ok(src.includes(name), name + ' missing from built app.js');
  assert.ok(src.includes('expProfileApply").addEventListener'), 'expProfileApply listener missing from built app.js');
  const c = load();
  const sample = {format:'pwnworkbench.elf.v1', binary:'./pwn', arch:'amd64', sha256:'a'.repeat(64),
    security:{pie:true, canary:false, nx:true, relro:'Full'},
    functions:['win','puts'], plt:['puts','system'], got:['puts']};
  const text = JSON.stringify(JSON.stringify(sample));
  const parsed = vm.runInContext('parseElfProfile(' + text + ')', c);
  assert.equal(parsed.binary, './pwn');
  assert.equal(parsed.arch, 'amd64');
  assert.equal(parsed.security.relro, 'Full');
  assert.throws(() => vm.runInContext('parseElfProfile(' + JSON.stringify(JSON.stringify({...sample, arch:'arm'})) + ')', c), /不支持/);
  c.node('exp-field-reentry').value = 'main';
  c.node('exp-field-target').value = 'win';
  vm.runInContext('applyElfProfile(parseElfProfile(' + text + '))', c);
  assert.equal(c.node('expBinary').value, './pwn');
  assert.equal(c.node('expArch').value, 'amd64');
  assert.match(c.node('expProfileStatus').textContent, /PIE 开/);
});
test('EXP required fields reject empty values instead of silently defaulting', () => {
  const c = load();
  assert.throws(() => c.generateExp('win', {...expFixture(c,'win'), target:''}), /不能为空/);
  assert.throws(() => c.generateExp('win', {...expFixture(c,'win'), reentry:''}), /不能为空/);
  assert.throws(() => c.generateExp('win', {...expFixture(c,'win'), binary:''}), /不能为空/);
  assert.throws(() => c.generateExp('libc-puts', {...expFixture(c,'libc-puts'), leakSymbol:''}), /不能为空/);
  assert.throws(() => c.generateExp('libc-puts', {...expFixture(c,'libc-puts'), libc:''}), /不能为空/);
  assert.throws(() => c.generateExp('plt', {...expFixture(c,'plt'), command:''}), /不能为空/);
  assert.throws(() => c.generateExp('csu', {...expFixture(c,'csu'), indirectSymbol:''}), /不能为空/);
  assert.throws(() => c.generateExp('nope', expFixture(c,'win')), /未知/);
});

test('architecture switch with a non-empty chain asks in-page before clearing', () => {
  const c=load();
  c.chain.push({name:'write',nr:1,code:'x',rax:'1'});
  c.setArch('i386');
  assert.equal(c.arch,'amd64','asking must not switch yet');
  assert.equal(c.chain.length,1,'asking must keep the chain');
  assert.equal(c.node('archConfirm').hidden,false,'confirm bar must show');
  assert.equal(c.pendingArch,'i386');
  assert.match(html,/id="archConfirm"[^>]*hidden/,'confirm bar is hidden by default');
  assert.match(html,/切换架构会清空当前调用链（链只属于一个架构）。要继续吗？/);
  c.node('archConfirmNo')._listeners.click();
  assert.equal(c.node('archConfirm').hidden,true,'cancel hides the bar');
  assert.equal(c.pendingArch,null);
  assert.equal(c.arch,'amd64','cancel keeps the architecture');
  assert.equal(c.chain.length,1,'cancel keeps the chain');
  c.setArch('i386');
  assert.equal(c.node('archConfirm').hidden,false,'second ask shows the bar again');
  c.node('archConfirmYes')._listeners.click();
  assert.equal(c.arch,'i386','accept switches the architecture');
  assert.equal(c.chain.length,0,'accept clears the chain');
  assert.equal(c.node('archConfirm').hidden,true,'accept hides the bar');
  c.setArch('amd64');
  assert.equal(c.arch,'amd64','empty chain switches immediately');
  assert.equal(c.node('archConfirm').hidden,true,'empty chain shows no bar');
  assert.equal(c.node('subLine').innerHTML.includes('第 4 个参数是 r10，不是 rcx'),true);
});
test('no native confirm() remains in the built output', () => {
  const js=fs.readFileSync(path.join(__dirname,'app.js'),'utf8');
  assert.doesNotMatch(js,/[^a-zA-Z]confirm\(/);
  assert.ok(js.includes('archConfirmYes'));
  assert.ok(js.includes('doSetArch'));
});

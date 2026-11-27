const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
function load() {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, { value: '', textContent: '', innerHTML: '', style: {},
      classList: { add(){}, remove(){}, toggle(){} }, addEventListener(){},
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
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
  vm.runInContext(script.replace(/selectByName\("write"\);\s*$/, ''), c);
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

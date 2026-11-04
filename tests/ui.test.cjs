const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync('app/static/app.js','utf8').replace(/\binit\(\);\s*$/,'');
const dummy={addEventListener(){}};
const ctx=vm.createContext({document:{querySelector(){return dummy;}},window:{addEventListener(){}},URL,console});
vm.runInContext(source,ctx);
test('source-controlled text is escaped, unsafe URL schemes are not linked',()=>{
  const html=vm.runInContext(`presentValue({name:'<img src=x onerror=alert(1)>',url:'javascript:alert(1)'})`,ctx);
  assert(!html.includes('<img'));
  assert(html.includes('&lt;img'));
  assert(!html.includes('href="javascript:'));
});
test('zero and false remain visible while missing values are omitted',()=>{
  const html=vm.runInContext(`presentValue({zero:0,flag:false,missing:null})`,ctx);
  assert(html.includes('>0<'));
  assert(html.includes('Нет'));
  assert(!html.includes('missing'));
});
test('large collections have a way to reveal the rest',()=>{
  const html=vm.runInContext(`presentValue(Array.from({length:45},(_,i)=>i),'records')`,ctx);
  assert(html.includes('data-more="records"'));
  assert(html.includes('осталось 15'));
});
test('utility navigation and JSON interface replace the previous visualization',()=>{
  const html=fs.readFileSync('app/static/index.html','utf8');
  assert(html.includes('id="toolNav"'));
  assert(html.includes('id="rawJson"'));
  assert(!html.includes('<svg'));
  assert(!html.includes('id="graph"'));
});

test('empty report stays empty with diagnostics, partial history overrides completed status',()=>{
  const nodes=new Map();
  ctx.document.querySelector=s=>{if(!nodes.has(s))nodes.set(s,{addEventListener(){}});return nodes.get(s);};
  vm.runInContext(`current={value:'example.org',kind:'domain',created:null,run:{status:'completed'},presentation:{state:'empty',empty:true,data:{},summary:{},items:[],notes:[],diagnostics:{stdout:'No results',exit_code:0}}};renderResult();`,ctx);
  assert.equal(nodes.get('#runStatus').textContent,'Ничего не найдено');
  assert(nodes.get('#results').innerHTML.includes('Ничего не найдено'));
  assert(nodes.get('#results').innerHTML.includes('Вывод утилиты и диагностика'));
  assert(!nodes.get('#results').innerHTML.includes('Найденные объекты'));
  vm.runInContext(`current.presentation={state:'partial',empty:false,data:{},summary:{},items:[],notes:[]};renderResult();`,ctx);
  assert.equal(nodes.get('#runStatus').textContent,'Частичные результаты');
  assert(!nodes.get('#results').innerHTML.includes('<strong>Ничего не найдено</strong>'));
});

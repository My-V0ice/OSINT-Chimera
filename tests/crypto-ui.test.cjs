const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const dummy={addEventListener(){}};
const ctx=vm.createContext({document:{querySelector(){return dummy;}},window:{addEventListener(){}},URL,console});
vm.runInContext(fs.readFileSync('app/static/crypto.js','utf8'),ctx);
vm.runInContext(fs.readFileSync('app/static/app.js','utf8').replace(/\binit\(\);\s*$/,''),ctx);
test('transfer table escapes addresses and preserves exact amounts',()=>{
 const html=vm.runInContext(`renderCrypto({rows:[{txid:'abc',from:['<img src=x onerror=alert(1)>'],to:['0xabc'],amount:'1.000000000000000001',asset:'ETH',network:'Ethereum',direction:'out'}],loaded:1,next_cursor:'cursor'})`,ctx);
 assert(html.includes('1.000000000000000001'));assert(!html.includes('<img'));assert(html.includes('&lt;img'));assert(html.includes('data-follow="0xabc"'));assert(html.includes('data-crypto-next'));
});
test('BTC spent output offers a manual next-transaction action',()=>{
 const html=vm.runInContext(`renderCrypto({rows:[{txid:'aaa',from:['from'],to:['to'],amount:'0',asset:'BTC',direction:'out',spent:true,spending_txid:'bbb'}],loaded:1,next_cursor:''})`,ctx);
 assert(html.includes('data-focus="bbb"'));assert(!html.includes('<svg'));assert(html.includes('0 BTC'));
});
test('empty filtered page and unknown token decimals remain explicit',()=>{
 const empty=vm.runInContext(`renderCrypto({rows:[],loaded:50,next_cursor:'next'})`,ctx);
 assert(empty.includes('записей по фильтрам нет'));assert(empty.includes('data-crypto-next'));
 const unknown=vm.runInContext(`renderCrypto({rows:[{txid:'x',from:[],to:[],amount:null,atomic:'1234567',asset:'Token',direction:'related'}],loaded:1})`,ctx);
 assert(unknown.includes('1234567 атом.'));
});

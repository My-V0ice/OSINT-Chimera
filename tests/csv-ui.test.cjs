const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const dummy={addEventListener(){}};
const ctx=vm.createContext({document:{querySelector(){return dummy;}},window:{addEventListener(){}},URL,console});
vm.runInContext(fs.readFileSync('app/static/app.js','utf8').replace(/\binit\(\);\s*$/,''),ctx);
vm.runInContext(fs.readFileSync('app/static/localcsv.js','utf8'),ctx);
test('CSV results preserve raw strings and escape every source-controlled field',()=>{
 const html=vm.runInContext(`renderCSVMatches({matches:[{source:'<img src=x>',line:2,data:{'<script>':'<img onerror=alert(1)>',id:'000123',empty:'',flag:'false'}}],has_more:true})`,ctx);
 assert(!html.includes('<img'));assert(!html.includes('<script>'));assert(html.includes('&lt;img'));assert(html.includes('000123'));assert(html.includes('Пусто'));assert(html.includes('false'));assert(html.includes('строка 2'));assert(html.includes('csvNextPage'));
});
test('no CSV matches have an explicit empty state',()=>{
 const html=vm.runInContext('renderCSVMatches({matches:[],has_more:false})',ctx);
 assert(html.includes('Ничего не найдено'));assert(!html.includes('csvNextPage'));
});

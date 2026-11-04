'use strict';
const cryptoTools=new Set(['esplora','trongrid','blockscout','graphsense','ethereumetl']);
let cryptoFormId='',cryptoTrail=[];
function cryptoForm(force=false){
  const box=document.querySelector('#cryptoOptions'),on=cryptoTools.has(selectedTool);box.hidden=!on;
  if(!on)return;if(!force&&cryptoFormId===selectedTool)return;cryptoFormId=selectedTool;
  const btc=selectedTool==='esplora',tron=selectedTool==='trongrid',etl=selectedTool==='ethereumetl';
  box.innerHTML=`<details open><summary>Параметры истории переводов</summary><div class="crypto-fields">
  <label>Сеть<select id="cryptoChain"><option value="1">Ethereum</option><option value="8453">Base</option><option value="10">Optimism</option><option value="534352">Scroll</option></select></label>
  <label>Операции<select id="cryptoEvent"><option value="native">Монеты</option><option value="token">Токены / TRC-20</option><option value="internal">Внутренние операции</option></select></label>
  <label>Страниц за запуск<input id="cryptoPages" type="number" min="1" max="3" value="1"></label>
  <label>Проверок расходования BTC<input id="cryptoSpends" type="number" min="0" max="5" value="2"></label>
  <label>Начальный блок<input id="cryptoStart" type="number" min="0" value="0"></label><label>Конечный блок<input id="cryptoEnd" type="number" min="0" value="0"></label>
  <label>Направление<select id="cryptoDirection"><option value="all">Все</option><option value="out">Исходящие</option><option value="in">Входящие</option></select></label>
  <label>Токен / контракт<input id="cryptoToken" maxlength="128" placeholder="Например USDT"></label>
  <label>От суммы<input id="cryptoMin" inputmode="decimal" maxlength="120"></label><label>До суммы<input id="cryptoMax" inputmode="decimal" maxlength="120"></label>
  <label>С даты<input id="cryptoSince" type="datetime-local"></label><label>По дату<input id="cryptoUntil" type="datetime-local"></label>
  </div><p class="note">Фильтры применяются к загруженным страницам. Продолжение по адресам — вручную; граф не строится. Диапазон Ethereum ETL — до 20 блоков.</p></details>`;
  $('#cryptoChain').closest('label').hidden=btc||tron||selectedTool==='graphsense';
  $('#cryptoEvent').closest('label').hidden=btc||selectedTool==='graphsense';$('#cryptoEvent').value=tron?'token':'native';
  $('#cryptoPages').closest('label').hidden=etl;$('#cryptoSpends').closest('label').hidden=!btc;
  for(const name of ['Start','End'])$('#crypto'+name).closest('label').hidden=!etl;
}
function cryptoPayload(cursor=''){
  if(!cryptoTools.has(selectedTool))return undefined;
  const number=(id,otherwise)=>{const n=Number($(id).value);return Number.isFinite(n)?n:otherwise;};
  const iso=id=>$(id).value?new Date($(id).value).toISOString():'';
  return {chain:$('#cryptoChain').value,event:$('#cryptoEvent').value,pages:number('#cryptoPages',1),spend_checks:number('#cryptoSpends',0),start_block:number('#cryptoStart',0),end_block:number('#cryptoEnd',0),direction:$('#cryptoDirection').value,asset_filter:$('#cryptoToken').value.trim(),minimum:$('#cryptoMin').value.trim(),maximum:$('#cryptoMax').value.trim(),since:iso('#cryptoSince'),until:iso('#cryptoUntil'),cursor};
}
function cryptoRestore(options){
  if(!cryptoTools.has(selectedTool)||!options)return;cryptoForm();
  const map={chain:'Chain',event:'Event',pages:'Pages',spend_checks:'Spends',start_block:'Start',end_block:'End',direction:'Direction',asset_filter:'Token',minimum:'Min',maximum:'Max'};
  for(const[k,id]of Object.entries(map))if(options[k]!==undefined)$('#crypto'+id).value=options[k];
  for(const[k,id]of [['since','Since'],['until','Until']]){const d=options[k]?new Date(options[k]):null;$('#crypto'+id).value=d&&!isNaN(d)?new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16):'';}
}
function cryptoAddresses(addresses,focus=''){
  return (addresses||[]).map(a=>`<button class="text-button wallet-address" data-follow="${esc(a)}" ${focus?`data-focus="${esc(focus)}"`:''}>${esc(a)}</button>`).join('<br>')||'—';
}
function renderCrypto(c){
  const dirs={in:'Входящий',out:'Исходящий',self:'На тот же адрес',related:'Связанный'};
  const limit=pageSizes.get('crypto')||30;const rows=c.rows.slice(0,limit).map(r=>`<tr><td>${r.timestamp!==null&&r.timestamp!==undefined?esc(new Date(r.timestamp*1000).toLocaleString('ru-RU')):'—'}</td><td>${cryptoAddresses(r.from)}</td><td>${cryptoAddresses(r.to)}</td><td>${esc(r.amount??(r.atomic+' атом.'))} ${esc(r.asset)}</td><td>${esc(dirs[r.direction]||r.direction)}<small>${esc(r.operation||'')}</small>${r.failed===true?'<strong class="danger">Операция неуспешна</strong>':''}</td><td>${r.tx_url?link(r.tx_url,r.txid):esc(r.txid)}${r.spent===false?'<small>Выход не потрачен</small>':r.spending_txid?`<small>Выход потрачен: ${esc(r.spending_txid)}</small>${cryptoAddresses(r.to,r.spending_txid)}`:''}</td></tr>`).join('');
  return `<div class="crypto-trail">${cryptoTrail.length?'Переходы: '+cryptoTrail.map(esc).join(' → '):''}</div><h3 class="section-title">Переводы · ${c.rows.length} / загружено ${c.loaded}</h3><div class="transfer-scroll"><table class="transfer-table"><thead><tr><th>Время</th><th>Отправители</th><th>Получатели / продолжить</th><th>Сумма и актив</th><th>Тип</th><th>Транзакция / расходование</th></tr></thead><tbody>${rows||'<tr><td colspan="6">На загруженных страницах записей по фильтрам нет.</td></tr>'}</tbody></table></div>${c.rows.length>limit?`<button class="text-button" data-more="crypto">Показать ещё переводы · осталось ${c.rows.length-limit}</button>`:''}${c.next_cursor?'<button type="button" class="button secondary" data-crypto-next>Загрузить следующие страницы</button>':''}<p class="note">Входы и выходы Bitcoin не образуют однозначного соответствия. Контрагенты, сдача, обмены и мосты требуют отдельного анализа.</p>`;
}
async function cryptoStart(value,options){
  if(submitting)return;const id=selectedTool,token=epoch;submitting=true;renderHeader();
  try{const created=await api('/tools/'+id+'/runs',{method:'POST',body:JSON.stringify({kind:$('#kind').value,value,options})});if(token===epoch&&id===selectedTool){await refreshHistory(token);await loadRun(created.id);}}
  catch(e){toast(e.message);}finally{submitting=false;renderHeader();}
}
document.querySelector('#results').addEventListener('click',e=>{
  const follow=e.target.closest('[data-follow]'),next=e.target.closest('[data-crypto-next]');
  if(!current?.presentation?.crypto)return;
  if(next){cryptoRestore(current.options||current.presentation.crypto.options);cryptoStart(current.value,cryptoPayload(current.presentation.crypto.next_cursor));}
  if(follow){if(cryptoTrail.length>=7){toast('Достигнут предел 6 ручных переходов. Начните новый поиск.');return;}if(!cryptoTrail.length)cryptoTrail.push(current.value);const options=cryptoPayload();options.focus_txid=follow.dataset.focus||'';cryptoTrail.push(follow.dataset.follow);$('#query').value=follow.dataset.follow;cryptoStart(follow.dataset.follow,options);}
});
document.querySelector('#settingsList').addEventListener('submit',e=>{
  const form=e.target.closest('[data-connection]');if(!form)return;e.preventDefault();
  settingsAction(async()=>{await api('/tools/'+form.dataset.connection+'/connection',{method:'PUT',body:JSON.stringify({endpoint:form.elements.endpoint.value.trim()})});toast('Подключение сохранено. Пустой URL удаляет настройку.');});
});

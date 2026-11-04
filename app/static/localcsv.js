'use strict';
let csvSources=[],csvKnown=new Set(),csvSelected=new Set(),csvTimer,csvBusy=false,csvPage=null;

async function chooseCSV(){
  selectedTool='localcsv';epoch++;cryptoTrail=[];openGroups.add('local');
  $('#welcome').hidden=true;$('#toolWorkspace').hidden=true;$('#csvWorkspace').hidden=false;
  clearResult();renderNav();location.hash='localcsv';
  csvPage=null;$('#csvResultStatus').textContent='Ожидание запроса';$('#csvResults').innerHTML='<div class="empty-state"><span>⌕</span><h3>Введите запрос для поиска</h3><p>Найденные записи появятся здесь, JSON — справа.</p></div>';
  try{await refreshCSVSources();}catch(e){toast(e.message);}
}
function renderCSVSources(){
  const ready=csvSources.filter(s=>s.status==='ready'&&!s.archived);
  $('#csvSourceCount').textContent=ready.length+' готово';
  $('#csvSources').innerHTML=csvSources.map(s=>`<article class="csv-source ${s.archived?'archived':''}"><label><input type="checkbox" data-csv-source="${esc(s.id)}" ${csvSelected.has(s.id)?'checked':''} ${s.status!=='ready'||s.archived?'disabled':''}><strong>${esc(s.name)}</strong></label><small>${s.archived?'В архиве':s.status==='ready'?'Готов':s.status==='importing'?'Индексируется…':'Ошибка импорта'} · ${Number(s.rows).toLocaleString('ru-RU')} записей · ${(s.size/1024).toFixed(1)} КиБ${s.encoding?' · '+esc(s.encoding):''}${s.delimiter?' · '+esc(s.delimiter==='\t'?'TAB':s.delimiter):''}</small>${s.message?`<p class="csv-warning">${esc(s.message)}</p>`:''}<button class="text-button" data-csv-archive="${esc(s.id)}" data-archived="${s.archived?'0':'1'}">${s.archived?'Восстановить':'В архив'}</button></article>`).join('')||'<p class="muted">Файлы пока не добавлены.</p>';
  const field=$('#csvField').value,fields=[...new Set(ready.filter(s=>csvSelected.has(s.id)).flatMap(s=>s.headers))].sort((a,b)=>a.localeCompare(b,'ru'));
  $('#csvField').innerHTML='<option value="">Все столбцы</option>'+fields.map(f=>`<option value="${esc(f)}">${esc(f)}</option>`).join('');
  if(fields.includes(field))$('#csvField').value=field;
  $('#csvSearchButton').disabled=csvBusy||!ready.some(s=>csvSelected.has(s.id));
}
async function refreshCSVSources(){
  clearTimeout(csvTimer);
  const data=await api('/local-csv/sources');csvSources=data.sources;
  for(const s of csvSources){if(!csvKnown.has(s.id)&&!s.archived)csvSelected.add(s.id);csvKnown.add(s.id);if(s.archived)csvSelected.delete(s.id);}
  renderCSVSources();
  if(selectedTool==='localcsv'&&csvSources.some(s=>s.status==='importing'))csvTimer=setTimeout(()=>refreshCSVSources().catch(e=>toast(e.message)),2000);
}
function renderCSVMatches(data){
  const html=data.matches.map((r,i)=>`<details class="record" ${data.matches.length<=3?'open':''}><summary><strong>${esc(r.source)}</strong> · строка ${r.line} · запись ${i+1}</summary><div><dl class="field-list">${Object.entries(r.data).map(([k,v])=>`<div class="field-row"><dt>${esc(k)}</dt><dd>${v===''?'<span class="muted">Пусто</span>':esc(v)}</dd></div>`).join('')}</dl></div></details>`).join('');
  return (html||'<div class="notice empty"><span>⌕</span><div><strong>Ничего не найдено</strong><small>В выбранных готовых файлах нет совпадений по этому запросу.</small></div></div>')+(data.has_more?'<button type="button" class="more-button" id="csvNextPage">Следующая страница →</button>':'');
}
async function searchCSV(payload){
  if(csvBusy)return;const token=++epoch;csvBusy=true;renderCSVSources();
  $('#csvResultStatus').textContent='Поиск…';$('#csvResults').innerHTML='<p class="muted">Поиск по локальному индексу…</p>';
  current=null;jsonText='';renderJson();
  try{
    const data=await api('/local-csv/search',{method:'POST',body:JSON.stringify(payload)});
    if(token!==epoch||selectedTool!=='localcsv')return;
    csvPage=data;current={id:'csv-'+Date.now(),created:data.created,run:{status:'completed'},raw_json:data};jsonText=JSON.stringify(data,null,2);renderJson();
    $('#csvResultStatus').textContent=data.returned?'На странице: '+data.returned+(data.has_more?' · есть ещё':''):'Ничего не найдено';
    $('#csvResults').innerHTML=renderCSVMatches(data);
  }catch(e){if(token===epoch&&selectedTool==='localcsv'){$('#csvResultStatus').textContent='Ошибка';$('#csvResults').innerHTML=`<div class="notice error">${esc(e.message)}</div>`;}}
  finally{csvBusy=false;renderCSVSources();}
}
$('#csvImportForm').addEventListener('submit',async e=>{
  e.preventDefault();const files=[...$('#csvFiles').files];if(!files.length)return;
  const encoding=$('#csvEncoding').value,delimiter=$('#csvDelimiter').value==='tab'?'\t':$('#csvDelimiter').value;
  $('#csvImportButton').disabled=true;let failures=[],duplicates=0;
  try{
    for(let i=0;i<files.length;i++){
      const file=files[i];$('#csvImportStatus').textContent=`Загрузка ${i+1} из ${files.length}: ${file.name}`;
      if(file.size>512*1024*1024){failures.push(file.name+': больше 512 МиБ');continue;}
      try{const result=await api('/local-csv/sources?'+new URLSearchParams({name:file.name,encoding,delimiter}),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});if(result.duplicate)duplicates++;await refreshCSVSources();}
      catch(error){failures.push(file.name+': '+error.message);}
    }
    $('#csvFiles').value='';$('#csvImportStatus').textContent=`Передано на импорт: ${files.length-failures.length-duplicates}. Уже были добавлены: ${duplicates}.`+(failures.length?' Ошибки: '+failures.join('; '):' Индексирование продолжается в фоне.');
  }finally{$('#csvImportButton').disabled=false;}
});
$('#csvRefreshSources').addEventListener('click',()=>refreshCSVSources().catch(e=>toast(e.message)));
$('#csvSources').addEventListener('change',e=>{const id=e.target.dataset.csvSource;if(id){e.target.checked?csvSelected.add(id):csvSelected.delete(id);renderCSVSources();}});
$('#csvSources').addEventListener('click',async e=>{
  const b=e.target.closest('[data-csv-archive]');if(!b)return;b.disabled=true;
  try{await api('/local-csv/sources/'+b.dataset.csvArchive+'/archive',{method:'PUT',body:JSON.stringify({archived:b.dataset.archived==='1'})});if(b.dataset.archived==='0')csvSelected.add(b.dataset.csvArchive);await refreshCSVSources();if(selectedTool==='localcsv'){epoch++;csvPage=null;clearResult();$('#csvResults').innerHTML='<p class="muted">Состав файлов изменён. Выполните поиск повторно.</p>';$('#csvResultStatus').textContent='Ожидание запроса';}}
  catch(error){toast(error.message);b.disabled=false;}
});
$('#csvSearchForm').addEventListener('submit',e=>{e.preventDefault();const sources=csvSources.filter(s=>s.status==='ready'&&!s.archived&&csvSelected.has(s.id)).map(s=>s.id);if(!sources.length){toast('Выберите хотя бы один готовый файл.');return;}searchCSV({query:$('#csvQuery').value,field:$('#csvField').value,mode:$('#csvMode').value,sources,cursor:0,limit:30});});
$('#csvResults').addEventListener('click',e=>{if(e.target.closest('#csvNextPage')&&csvPage?.has_more)searchCSV({...csvPage.query,cursor:csvPage.next_cursor});});

const toast=document.getElementById('toast');
function showToast(message){if(!toast)return;toast.textContent=message;toast.classList.add('show');clearTimeout(window.__toast);window.__toast=setTimeout(()=>toast.classList.remove('show'),2800)}
const menuBtn=document.getElementById('menuBtn'),sidebar=document.getElementById('sidebar');if(menuBtn&&sidebar)menuBtn.onclick=()=>sidebar.classList.toggle('open');
const current=location.pathname.replace(/\/$/,'')||'/';document.querySelectorAll('.nav-link').forEach(a=>{const p=new URL(a.href).pathname.replace(/\/$/,'')||'/';if(p===current)a.classList.add('active')});
async function getJSON(url,options={}){const r=await fetch(url,options);let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.message||'Request failed');return d}
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
window.showToast=showToast;window.getJSON=getJSON;window.esc=esc;

const logoutBtn=document.getElementById('logoutBtn'); if(logoutBtn){logoutBtn.onclick=async()=>{await fetch('/api/auth/logout',{method:'POST'});location='/login'}}

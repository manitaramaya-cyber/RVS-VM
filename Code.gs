var ADMIN_KEY='rav-fleet-x9k2m7'; // ใช้เลือกหน้าเว็บเท่านั้น ไม่ใช่การยืนยันสิทธิ์ Admin
var SHEETS={STAFF:'Staff',REQUESTS:'Requests',VEHICLES:'Vehicles',DRIVERS:'Drivers'};
var APP_VERSION='V1.2.9';
var REQ_DRIVER_NAME_COL_='ชื่อผู้ขับรถที่ผู้ขอระบุ'; // V1.2.9: ชื่อผู้ขับรถที่ผู้ขอใช้รถระบุเอง (แยกจาก DRIVER_COL_ ที่ Admin จัดสรร ห้ามเขียนทับกัน)
var REQ_PHONE_COL_='เบอร์โทรผู้ขอใช้รถ'; // V1.2.9: เบอร์ติดต่อผู้ขอใช้รถ (เฉพาะ Admin เห็น ไม่ส่งออกใน getBookingsForMonth)
var DRIVER_COL_='คนขับที่จัด'; // คอลัมน์ในชีต Requests (ถ้ายังไม่มี ระบบจะสร้างให้อัตโนมัติเมื่อบันทึกคนขับครั้งแรก)
var STATUS={PENDING:'รอดำเนินการ',APPROVED:'อนุมัติแล้ว',ASSIGNED:'จัดรถแล้ว',IN_USE:'กำลังใช้งาน',DONE:'เสร็จสิ้น',CANCELLED:'ยกเลิก',REJECTED:'ปฏิเสธ'};
var ADMIN_NAMES=['Admin01','Admin02','Admin03','Admin00','SAdmin'];
var AUDIT_SHEET_NAME='AuditLog';

// Admin credentials are stored as SHA-256 digests; plaintext codes are not embedded in client HTML.
var ADMIN_ACCOUNTS_={
  'Admin01':{digest:'d084596dc6649c7de0998da2fa497bfa3f753dbab12b4e10fea77c9f827c5808',role:'ADMIN'},
  'Admin02':{digest:'467a48bd7961dac07cdfb93da50aaab496196084df27e7e689d0798618073440',role:'ADMIN'},
  'Admin03':{digest:'7ae88b346933e7e916cd46609b2e33ea71ea378aa0686f45adc955d6013f6881',role:'ADMIN'},
  'Admin00':{digest:'6a5d85f1688ffeb791fe16aa2c612acaf14dde80f2fa4e71ab853cb53baab757',role:'ADMIN'},
  'SAdmin':{digest:'525018ebae7f474dafbb62fa6de7362c533c219d730b30dc12681da0bf7580f9',role:'SUPERADMIN'}
};
var ADMIN_SESSION_PREFIX_='RVSVM_ADMIN_SESSION_';
var ADMIN_SESSION_TTL_SECONDS_=21600;
function sha256Hex_(value){
  var bytes=Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,String(value||''),Utilities.Charset.UTF_8);
  return bytes.map(function(b){var n=(b+256)%256;return ('0'+n.toString(16)).slice(-2);}).join('');
}
function loginAdmin(account,accessCode){
  account=String(account||'').trim(); accessCode=String(accessCode||'');
  var cache=CacheService.getScriptCache(),attemptKey='RVSVM_ADMIN_LOGIN_FAIL_'+account;
  var attempts=Number(cache.get(attemptKey)||0);
  if(attempts>=5)throw new Error('บัญชีนี้ถูกพักการเข้าสู่ระบบชั่วคราว กรุณารอ 15 นาทีแล้วลองใหม่');
  var cfg=ADMIN_ACCOUNTS_[account];
  if(!cfg||sha256Hex_(accessCode)!==cfg.digest){
    attempts++;cache.put(attemptKey,String(attempts),900);
    throw new Error(attempts>=5?'กรอกรหัสผิดหลายครั้ง บัญชีถูกพักชั่วคราว 15 นาที':'ชื่อบัญชีหรือรหัสเข้าระบบไม่ถูกต้อง');
  }
  cache.remove(attemptKey);
  var token=Utilities.getUuid().replace(/-/g,'')+Utilities.getUuid().replace(/-/g,'');
  var session={account:account,role:cfg.role,issuedAt:new Date().toISOString()};
  cache.put(ADMIN_SESSION_PREFIX_+token,JSON.stringify(session),ADMIN_SESSION_TTL_SECONDS_);
  appendAuditLog_('ADMIN_LOGIN','',account,'','','',{type:'ADMIN_LOGIN',account:account,role:cfg.role});
  return {ok:true,token:token,admin:{account:account,role:cfg.role,displayName:account},expiresInSeconds:ADMIN_SESSION_TTL_SECONDS_};
}
function getAdminSession(token){return {ok:true,admin:getAdminSession_(token)};}
function logoutAdmin(token){
  token=String(token||'').trim();var cache=CacheService.getScriptCache(),raw=token?cache.get(ADMIN_SESSION_PREFIX_+token):null;
  if(raw){try{var s=JSON.parse(raw);appendAuditLog_('ADMIN_LOGOUT','',s.account||'','','','',{type:'ADMIN_LOGOUT',account:s.account||''});}catch(e){}cache.remove(ADMIN_SESSION_PREFIX_+token);}return {ok:true};
}
function getAdminSession_(token){
  token=String(token||'').trim();if(!token)throw new Error('กรุณาเข้าสู่ระบบผู้ดูแล');
  var raw=CacheService.getScriptCache().get(ADMIN_SESSION_PREFIX_+token);if(!raw)throw new Error('เซสชันผู้ดูแลหมดอายุ กรุณาเข้าสู่ระบบใหม่');
  var session;try{session=JSON.parse(raw);}catch(e){throw new Error('เซสชันผู้ดูแลไม่ถูกต้อง');}
  var cfg=ADMIN_ACCOUNTS_[session.account];if(!cfg||cfg.role!==session.role)throw new Error('บัญชีนี้ไม่มีสิทธิ์ผู้ดูแล');
  return {account:session.account,role:session.role,displayName:session.account};
}
function requireAdminSession_(token,permission){
  var admin=getAdminSession_(token);
  if(permission==='superadmin'&&admin.role!=='SUPERADMIN')throw new Error('รายการนี้สงวนสิทธิ์สำหรับ SAdmin');
  return admin;
}

function doGet(e){
  var key=e&&e.parameter&&e.parameter.key;
  return HtmlService.createTemplateFromFile(key===ADMIN_KEY?'Admin':'Calendar').evaluate().setTitle('ระบบจองรถยนต์โรงเรียน RAV').addMetaTag('viewport','width=device-width, initial-scale=1, viewport-fit=cover').setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
function include(filename){return HtmlService.createHtmlOutputFromFile(filename).getContent();}
function ss_(){return SpreadsheetApp.getActiveSpreadsheet();}
function sheet_(name){var sh=ss_().getSheetByName(name);if(!sh)throw new Error('ไม่พบชีทชื่อ "'+name+'" กรุณาสร้างชีทนี้ก่อน');return sh;}
function rowsToObjects_(sheet){var values=sheet.getDataRange().getValues();if(values.length<2)return [];var headers=values[0],out=[];for(var i=1;i<values.length;i++){var row=values[i];if(row.join('')==='')continue;var obj={};for(var c=0;c<headers.length;c++)obj[headers[c]]=row[c];obj._row=i+1;out.push(obj);}return out;}
function formatDate_(v){if(!v)return '';var d=v instanceof Date?v:new Date(v);if(isNaN(d.getTime()))return String(v);return Utilities.formatDate(d,Session.getScriptTimeZone(),'yyyy-MM-dd');}
function formatTime_(v){if(!v)return '';if(v instanceof Date)return Utilities.formatDate(v,Session.getScriptTimeZone(),'HH:mm');var s=String(v).trim();if(/^\d{1,2}:\d{2}:\d{2}$/.test(s))return s.substring(0,5);return s;}
// ===== V1.2.9: คอลัมน์ใหม่ + ตัวช่วยอ่าน/พิมพ์ =====
function ensureRequestColumns_(sh){
  // เพิ่มหัวคอลัมน์ใหม่ต่อท้ายชีต Requests เมื่อยังไม่มี (ไม่แตะคอลัมน์/ข้อมูลเดิม)
  var lastCol=Math.max(sh.getLastColumn(),1),headers=sh.getRange(1,1,1,lastCol).getValues()[0];
  [REQ_DRIVER_NAME_COL_,REQ_PHONE_COL_].forEach(function(name){
    if(headers.indexOf(name)>=0)return;
    var need=headers.length+1;
    if(sh.getMaxColumns()<need)sh.insertColumnsAfter(sh.getMaxColumns(),need-sh.getMaxColumns());
    sh.getRange(1,need).setValue(name);
    if(name===REQ_PHONE_COL_)sh.getRange(2,need,Math.max(sh.getMaxRows()-1,1),1).setNumberFormat('@'); // เก็บเป็นข้อความ กันเลข 0 นำหน้าหาย
    headers.push(name);
  });
  return headers;
}
function cleanPhone_(v){return String(v==null?'':v).trim().replace(/[^\d+\-\s()]/g,'').slice(0,30);}
function formatPhone_(v){var s=String(v==null?'':v).trim();return /^\d{9}$/.test(s)?'0'+s:s;} // ข้อมูลที่ Sheets แปลงเป็นตัวเลขจนเลข 0 นำหน้าหาย
function requestToClient_(r){
  return {id:String(r.id||''),name:String(r['ชื่อ-นามสกุล']||''),position:String(r['ตำแหน่ง']||''),department:String(r['สังกัด']||''),destination:String(r['ปลายทาง']||''),purpose:String(r['วัตถุประสงค์']||''),dateGo:formatDate_(r['วันที่ไป']),timeGo:formatTime_(r['เวลาไป']),dateBack:formatDate_(r['วันที่กลับ']),timeBack:formatTime_(r['เวลากลับ']),needDriver:String(r['ต้องการคนขับ']||''),companionCount:Number(r['จำนวนผู้ร่วมเดินทาง'])||0,companionNames:String(r['รายชื่อผู้ร่วมเดินทาง']||''),isLarge:String(r['ทริปใหญ่']||''),students:Number(r['จำนวนนักเรียน'])||0,teachers:Number(r['จำนวนครู'])||0,others:Number(r['จำนวนอื่นๆ'])||0,status:String(r['สถานะ']||''),vehicles:String(r['รถที่จัด']||''),driver:String(r[DRIVER_COL_]||''),requestedDriver:String(r[REQ_DRIVER_NAME_COL_]||''),requesterPhone:formatPhone_(r[REQ_PHONE_COL_]),recordedBy:String(r['ผู้บันทึก']||''),note:String(r['หมายเหตุ']||'')};
}
// อ่านอย่างเดียว: ดึงข้อมูลล่าสุดของคำขอ 1 รายการตาม Request ID สำหรับพิมพ์ใบอนุญาต (ไม่เปลี่ยนสถานะ ไม่เขียนชีต ไม่เขียน AuditLog)
function getRequestForPrint(id,adminToken){
  requireAdminSession_(adminToken);
  id=String(id==null?'':id).trim();
  if(!id)throw new Error('ไม่ได้ระบุรหัสคำขอ (Request ID)');
  var found=findRequestRowById_(id);
  if(!found)throw new Error('ไม่พบรายการคำขอ: '+id);
  return requestToClient_(found.object);
}
// ===== V1.2.9: สรุปรายงานการใช้รถประจำวัน + ส่งเข้า LINE กลุ่ม =====
// ตั้งค่า LINE ใน Project Settings > Script properties (ไม่ฝังใน Client/ชีต):
//   LINE_CHANNEL_TOKEN = Channel access token (long-lived) ของ LINE Official Account ที่เปิด Messaging API
//   LINE_GROUP_ID      = groupId ของกลุ่มไลน์ที่เชิญบอทเข้าไปแล้ว (ขึ้นต้นด้วย C)
var LINE_TOKEN_PROP_='LINE_CHANNEL_TOKEN',LINE_GROUP_PROP_='LINE_GROUP_ID',LINE_LASTSENT_PROP_='LINE_LAST_SENT_DATE';
var DAILY_REPORT_STATUSES_=[STATUS.APPROVED,STATUS.ASSIGNED,STATUS.IN_USE,STATUS.DONE];
function todayKey_(){return Utilities.formatDate(new Date(),'Asia/Bangkok','yyyy-MM-dd');}
function thaiLongDate_(key){
  var m=String(key||'').match(/^(\d{4})-(\d{2})-(\d{2})$/);if(!m)return String(key||'');
  var d=new Date(Number(m[1]),Number(m[2])-1,Number(m[3]));
  var days=['อาทิตย์','จันทร์','อังคาร','พุธ','พฤหัสบดี','ศุกร์','เสาร์'];
  var months=['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน','พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม','กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม'];
  return 'วัน'+days[d.getDay()]+'ที่ '+Number(m[3])+' '+months[Number(m[2])-1]+' '+(Number(m[1])+543);
}
function vehicleLabel_(name,vehRows){
  name=String(name||'').trim();if(!name)return '';
  var plateCols=['ทะเบียน','เลขทะเบียน','ป้ายทะเบียน','เลขทะเบียนรถ','plate','Plate'];
  for(var i=0;i<vehRows.length;i++){
    if(String(vehRows[i]['ชื่อรถ']||'').trim()!==name)continue;
    for(var j=0;j<plateCols.length;j++){var p=String(vehRows[i][plateCols[j]]||'').trim();if(p&&name.indexOf(p)<0)return name+' '+p;}
  }
  return name;
}
function reportDriverName_(r){
  // กติกาเดียวกับใบอนุญาต: ต้องการคนขับ -> คนขับที่ Admin จัดสรร / ไม่ต้องการ -> ชื่อที่ผู้ขอระบุ
  return String(r.needDriver||'').trim()==='ต้องการ'?String(r.driver||'').trim():String(r.requestedDriver||'').trim();
}
function buildDailyReport_(dateKey){
  // รายงานเฉพาะคำขอที่ อนุมัติ/จัดรถแล้ว + มีรถที่จัด + มีผู้ขับรถ (ข้อมูลไม่ครบ -> ไม่รายงาน แต่แจ้งเตือนใน warnings)
  var vehRows=rowsToObjects_(sheet_(SHEETS.VEHICLES));
  var cand=rowsToObjects_(sheet_(SHEETS.REQUESTS)).map(requestToClient_).filter(function(r){
    return r.dateGo===dateKey&&DAILY_REPORT_STATUSES_.indexOf(r.status)>=0;
  }).sort(function(a,b){return String(a.timeGo).localeCompare(String(b.timeGo));});
  var warnings=[],blocks=[],skipped=0;
  cand.forEach(function(r){
    var vlist=String(r.vehicles||'').split(',').map(function(x){return vehicleLabel_(x,vehRows);}).filter(Boolean);
    var drv=reportDriverName_(r),who=r.name+' ('+(r.timeGo||'-')+' น.)',why=[];
    if(!vlist.length)why.push('ยังไม่ได้จัดรถ');
    if(!drv)why.push('ยังไม่มีผู้ขับรถ');
    if(why.length){skipped++;warnings.push('ไม่นำไปรายงาน — '+who+': '+why.join(' / '));return;}
    var total=(Number(r.students)||0)+(Number(r.teachers)||0)+(Number(r.others)||0);if(total<=0)total=Number(r.companionCount)||0;
    if(!total)warnings.push(who+': ไม่ระบุจำนวนผู้ร่วมเดินทาง (รายงานเป็น 0 คน)');
    var purpose=String(r.purpose||'').trim(),dest=String(r.destination||'').trim();
    var what=purpose+((dest&&purpose.indexOf(dest)<0)?' ณ '+dest:'');
    var lines=['เวลา '+(r.timeGo||'-')+' น.'];
    vlist.forEach(function(v){lines.push('🚐'+v);});
    lines.push('🙎🏻ผู้ขับรถ  '+drv);
    lines.push('');lines.push('-'+what);lines.push('ผู้ร่วมเดินทาง '+total+' คน');
    blocks.push(lines.join('\n'));
  });
  var text=blocks.length?('แจ้งการใช้รถโรงเรียน\n'+thaiLongDate_(dateKey)+'\n\n'+blocks.join('\n\n')+'\n\n🙏🏻ขอบคุณครับ🙏🏻'):'';
  return {dateKey:dateKey,dateText:thaiLongDate_(dateKey),count:blocks.length,skippedCount:skipped,warnings:warnings,text:text};
}
function lineConfigured_(){var p=PropertiesService.getScriptProperties();return !!(p.getProperty(LINE_TOKEN_PROP_)&&p.getProperty(LINE_GROUP_PROP_));}
function autoTriggerOn_(){try{return ScriptApp.getProjectTriggers().some(function(t){return t.getHandlerFunction()==='dailyLineReportJob';});}catch(e){return null;}}
// อ่านอย่างเดียว: สร้างข้อความรายงานของวันที่ระบุ (ไม่ส่ง ไม่เขียนชีต)
function getDailyReport(dateKey,adminToken){
  requireAdminSession_(adminToken);
  dateKey=String(dateKey||'').trim()||todayKey_();
  if(!/^\d{4}-\d{2}-\d{2}$/.test(dateKey))throw new Error('รูปแบบวันที่ไม่ถูกต้อง');
  var rep=buildDailyReport_(dateKey);rep.lineConfigured=lineConfigured_();rep.autoTrigger=autoTriggerOn_();
  return rep;
}
function sendLineText_(text){
  var p=PropertiesService.getScriptProperties(),token=p.getProperty(LINE_TOKEN_PROP_),to=p.getProperty(LINE_GROUP_PROP_);
  if(!token||!to)throw new Error('ยังไม่ได้ตั้งค่า LINE (Script properties: '+LINE_TOKEN_PROP_+' และ '+LINE_GROUP_PROP_+')');
  var chunks=[],cur='';
  String(text).split('\n\n').forEach(function(part){if((cur+'\n\n'+part).length>4800&&cur){chunks.push(cur);cur=part;}else cur=cur?cur+'\n\n'+part:part;});
  if(cur)chunks.push(cur);
  chunks.forEach(function(c){
    var res=UrlFetchApp.fetch('https://api.line.me/v2/bot/message/push',{method:'post',contentType:'application/json',headers:{Authorization:'Bearer '+token},payload:JSON.stringify({to:to,messages:[{type:'text',text:c}]}),muteHttpExceptions:true});
    var code=res.getResponseCode();
    if(code!==200)throw new Error('LINE ตอบกลับ '+code+': '+String(res.getContentText()||'').slice(0,200));
  });
}
// Admin กดส่งเอง (ส่งข้อความที่แก้ไขแล้วในช่องได้; ถ้าว่างใช้ข้อความที่ระบบสร้าง)
function sendDailyReportToLine(dateKey,text,adminToken){
  var admin=requireAdminSession_(adminToken);
  dateKey=String(dateKey||'').trim()||todayKey_();
  text=String(text||'').trim()||buildDailyReport_(dateKey).text;
  if(!text)throw new Error('ไม่มีรายการใช้รถที่อนุมัติแล้วในวันที่เลือก จึงไม่ส่งข้อความ');
  sendLineText_(text);
  appendAuditLog_('DAILY_REPORT_SENT','',admin.account,'','','',{type:'DAILY_REPORT_SENT',date:dateKey,length:text.length});
  return {ok:true};
}
// ฟังก์ชันที่ Trigger เรียกทุกเช้า: ส่งเฉพาะเมื่อมีรายการ และไม่ส่งซ้ำในวันเดียวกัน
function dailyLineReportJob(){
  var key=todayKey_(),props=PropertiesService.getScriptProperties();
  if(props.getProperty(LINE_LASTSENT_PROP_)===key)return;
  var rep=buildDailyReport_(key);
  if(!rep.count)return;
  sendLineText_(rep.text);
  props.setProperty(LINE_LASTSENT_PROP_,key);
  try{appendAuditLog_('DAILY_REPORT_AUTO','','system','','','',{type:'DAILY_REPORT_AUTO',date:key,trips:rep.count});}catch(e){}
}
// เจ้าของระบบรันครั้งเดียวจาก Apps Script Editor: ตั้งเวลาส่งอัตโนมัติ ~05:30 น. ทุกวัน (คลาดเคลื่อนได้ ±15 นาที)
function installDailyLineTrigger(){
  removeDailyLineTrigger();
  ScriptApp.newTrigger('dailyLineReportJob').timeBased().atHour(5).nearMinute(30).everyDays(1).inTimezone('Asia/Bangkok').create();
  return 'ตั้งเวลาส่งอัตโนมัติแล้ว (ประมาณ 05:30 น. ทุกวัน)';
}
function removeDailyLineTrigger(){
  ScriptApp.getProjectTriggers().forEach(function(t){if(t.getHandlerFunction()==='dailyLineReportJob')ScriptApp.deleteTrigger(t);});
  return 'ยกเลิกการส่งอัตโนมัติแล้ว';
}
// รันครั้งเดียวจาก Editor เพื่ออนุมัติสิทธิ์ใหม่ (UrlFetch + Trigger) ก่อน Deploy เป็นเวอร์ชันใหม่ — ไม่ส่งข้อความใดๆ
function authorizeLineReport(){
  var r=UrlFetchApp.fetch('https://api.line.me/v2/bot/info',{muteHttpExceptions:true});
  return 'อนุมัติสิทธิ์แล้ว (LINE ตอบ '+r.getResponseCode()+' เป็นเรื่องปกติหากยังไม่ได้ตั้งค่า token) triggers='+ScriptApp.getProjectTriggers().length;
}
function getVehicles(adminToken){requireAdminSession_(adminToken);return rowsToObjects_(sheet_(SHEETS.VEHICLES));}
function getDrivers(adminToken){requireAdminSession_(adminToken);return getDriverNames_().map(function(n){return {name:n};});}
function getDriverNames_(){
  var sh=sheet_(SHEETS.DRIVERS),values=sh.getDataRange().getValues();
  if(values.length<2)return [];
  var headers=values[0].map(function(h){return String(h||'').trim();});
  var cands=['ชื่อ-นามสกุล','ชื่อคนขับ','ชื่อพนักงานขับรถ','พนักงานขับรถ','คนขับ','ชื่อ','Name','name','Driver','driver'];
  var idx=-1;for(var i=0;i<cands.length&&idx<0;i++)idx=headers.indexOf(cands[i]);
  if(idx<0)idx=0; // ไม่พบหัวคอลัมน์ที่รู้จัก ใช้คอลัมน์แรก
  var out=[],seen={};
  for(var r=1;r<values.length;r++){var n=String(values[r][idx]||'').trim();if(n&&!seen[n]){seen[n]=1;out.push(n);}}
  return out;
}
function driverRangeKey_(o){
  var d1=formatDate_(o['วันที่ไป']),d2=formatDate_(o['วันที่กลับ'])||d1;
  var t1=normalizeTimeValue_(o['เวลาไป']||'00:00'),t2=normalizeTimeValue_(o['เวลากลับ']||o['เวลาไป']||'23:59');
  return {start:d1+'T'+t1,end:d2+'T'+t2,d1:d1,d2:d2,t1:t1,t2:t2};
}
function findDriverConflict_(rows,target,driver){
  var active=[STATUS.APPROVED,STATUS.ASSIGNED,STATUS.IN_USE],me=driverRangeKey_(target);
  for(var i=0;i<rows.length;i++){
    var o=rows[i];if(String(o.id)===String(target.id))continue;
    if(String(o[DRIVER_COL_]||'').trim()!==driver)continue;
    if(active.indexOf(String(o['สถานะ']||''))<0)continue;
    var k=driverRangeKey_(o);
    if(me.start<k.end&&k.start<me.end)return {row:o,range:k};
  }
  return null;
}
function thaiDateText_(ymd){
  var m=String(ymd||'').match(/^(\d{4})-(\d{2})-(\d{2})/);if(!m)return '-';
  var months=['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน','พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม','กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม'];
  return 'วันที่ '+Number(m[3])+' เดือน '+months[Number(m[2])-1]+' พ.ศ. '+(Number(m[1])+543);
}
function getAdminNames(adminToken){requireAdminSession_(adminToken);return ADMIN_NAMES;}
function getStatusList(adminToken){requireAdminSession_(adminToken);return Object.keys(STATUS).map(function(k){return STATUS[k];});}

function lookupStaffById(id,adminToken){requireAdminSession_(adminToken);return lookupStaffByIdWithoutAuth_(id);}

function lookupStaffByIdWithoutAuth_(id){
  id=String(id||'').trim();if(!id)return null;
  var rows=rowsToObjects_(sheet_(SHEETS.STAFF));
  var idHeaders=['รหัสบุคลากร','รหัสประจำตัว','Staff ID','staffId','ID','รหัส'];
  var nameHeaders=['ชื่อ-นามสกุล','ชื่อ','Name','name'];
  var positionHeaders=['ตำแหน่ง','Position','position'];
  var departmentHeaders=['สังกัด','แผนก','Department','department'];
  function pick(r,list){for(var i=0;i<list.length;i++)if(r[list[i]]!==undefined&&String(r[list[i]]).trim()!=='')return String(r[list[i]]).trim();return '';}
  for(var i=0;i<rows.length;i++)if(normalizeStaffId_(pick(rows[i],idHeaders))===normalizeStaffId_(id))return {id:normalizeStaffId_(id),name:pick(rows[i],nameHeaders),position:pick(rows[i],positionHeaders),department:pick(rows[i],departmentHeaders)};
  return null;
}

function normalizeStaffId_(value){
  var id=String(value===null||value===undefined?'':value).trim();
  return /^\d{1,6}$/.test(id)?id.padStart(6,'0'):id;
}

function getBookingsForMonth(year,month){
  year=Number(year);month=Number(month);
  if(!year||month<1||month>12)throw new Error('เดือนหรือปีไม่ถูกต้อง');
  var monthStart=year+'-'+String(month).padStart(2,'0')+'-01';
  var nextMonth=new Date(year,month,1);
  var monthEnd=Utilities.formatDate(new Date(nextMonth.getTime()-86400000),Session.getScriptTimeZone(),'yyyy-MM-dd');
  return rowsToObjects_(sheet_(SHEETS.REQUESTS)).filter(function(r){
    var start=formatDate_(r['วันที่ไป']);
    if(!start||start.length<10)return false;
    var end=formatDate_(r['วันที่กลับ'])||start;
    var status=String(r['สถานะ']||STATUS.PENDING);
    return start<=monthEnd&&end>=monthStart&&status!==STATUS.CANCELLED&&status!==STATUS.REJECTED;
  }).map(function(r){return {
    name:String(r['ชื่อ-นามสกุล']||''),
    position:String(r['ตำแหน่ง']||''),
    department:String(r['สังกัด']||''),
    destination:String(r['ปลายทาง']||''),
    purpose:String(r['วัตถุประสงค์']||''),
    dateGo:formatDate_(r['วันที่ไป']),timeGo:formatTime_(r['เวลาไป']),
    dateBack:formatDate_(r['วันที่กลับ']),timeBack:formatTime_(r['เวลากลับ']),
    needDriver:String(r['ต้องการคนขับ']||''),
    companionCount:Number(r['จำนวนผู้ร่วมเดินทาง'])||0,
    companionNames:String(r['รายชื่อผู้ร่วมเดินทาง']||''),
    students:Number(r['จำนวนนักเรียน'])||0,
    teachers:Number(r['จำนวนครู'])||0,
    others:Number(r['จำนวนอื่นๆ'])||0,
    status:String(r['สถานะ']||STATUS.PENDING),
    vehicles:String(r['รถที่จัด']||''),
    driver:String(r[DRIVER_COL_]||''),
    requestedDriver:String(r[REQ_DRIVER_NAME_COL_]||''),
    note:String(r['หมายเหตุ']||'')
  };});
}
function getAllRequests(adminToken){requireAdminSession_(adminToken);return rowsToObjects_(sheet_(SHEETS.REQUESTS)).map(requestToClient_).sort(function(a,b){return a.dateGo<b.dateGo?1:a.dateGo>b.dateGo?-1:0;});}

function saveRequest(data,sessionToken){
  data=data||{};
  var adminSession=null;
  try{if(sessionToken)adminSession=getAdminSession_(sessionToken);}catch(adminErr){adminSession=null;}
  // Public staff booking is intentionally available without staff login.
  // Do not trust a client-supplied identity as verified; keep it as submitted information.
  data.staffId=String(data.staffId||'').trim().slice(0,30);
  data.name=String(data.name||'').trim().slice(0,120);
  data.position=String(data.position||'').trim().slice(0,120);
  data.department=String(data.department||'').trim().slice(0,120);
  data.destination=String(data.destination||'').trim().slice(0,250);
  data.purpose=String(data.purpose||'').trim().slice(0,500);
  data.companionNames=String(data.companionNames||'').trim().slice(0,2000);
  data.note=String(data.note||'').trim().slice(0,1000);
  data.requestedDriver=String(data.requestedDriver||'').trim().slice(0,120);
  data.requesterPhone=cleanPhone_(data.requesterPhone);
  var needDriverFlag=(data.needDriver===true||data.needDriver==='1'||data.needDriver==='ต้องการ');
  if(needDriverFlag)data.requestedDriver=''; // ขอคนขับจากโรงเรียน: ไม่เก็บชื่อที่ผู้ขอระบุ (Admin จัดสรรเองในคอลัมน์ DRIVER_COL_)
  if(adminSession)data.recordedBy=adminSession.account;else data.recordedBy='ส่งผ่านแบบฟอร์มสาธารณะ';
  if(!data.name||!data.destination||!data.purpose||!String(data.dateGo||'').trim()||!String(data.timeGo||'').trim()) throw new Error('กรุณากรอกชื่อ ปลายทาง วัตถุประสงค์ วันที่ไป และเวลาไป');
  if(!needDriverFlag&&!data.requestedDriver)throw new Error('กรณีไม่ต้องการคนขับจากโรงเรียน กรุณาระบุชื่อผู้ขับรถ');
  var phoneDigits=data.requesterPhone.replace(/\D/g,'');
  if(!adminSession&&!phoneDigits)throw new Error('กรุณากรอกเบอร์โทรศัพท์ผู้ขอใช้รถ');
  if(phoneDigits&&(phoneDigits.length<9||phoneDigits.length>15))throw new Error('เบอร์โทรศัพท์ไม่ถูกต้อง');
  if(data.dateBack && String(data.dateBack)<String(data.dateGo)) throw new Error('วันที่กลับต้องไม่อยู่ก่อนวันที่เดินทางไป');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(String(data.dateGo))||!/^\d{2}:\d{2}$/.test(String(data.timeGo)))throw new Error('รูปแบบวันที่หรือเวลาไม่ถูกต้อง');
  if(data.dateBack&&!/^\d{4}-\d{2}-\d{2}$/.test(String(data.dateBack)))throw new Error('รูปแบบวันที่กลับไม่ถูกต้อง');
  if(data.timeBack&&!/^\d{2}:\d{2}$/.test(String(data.timeBack)))throw new Error('รูปแบบเวลากลับไม่ถูกต้อง');
  var lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    var sh=sheet_(SHEETS.REQUESTS);ensureRequestColumns_(sh);
    var headers=sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0],row=new Array(headers.length).fill(''),id='R'+new Date().getTime()+'-'+Utilities.getUuid().substring(0,6).toUpperCase();
    var map={id:id,timestamp:new Date(),'รหัสบุคลากร':data.staffId||'','ชื่อ-นามสกุล':data.name,'ตำแหน่ง':data.position,'สังกัด':data.department,'ปลายทาง':data.destination,'วัตถุประสงค์':data.purpose,'วันที่ไป':data.dateGo,'เวลาไป':data.timeGo,'วันที่กลับ':data.dateBack||'','เวลากลับ':data.timeBack||'','ต้องการคนขับ':data.needDriver===true||data.needDriver==='1'||data.needDriver==='ต้องการ'?'ต้องการ':'ไม่ต้องการ','จำนวนผู้ร่วมเดินทาง':Number(data.companionCount)||0,'รายชื่อผู้ร่วมเดินทาง':data.companionNames||'','ทริปใหญ่':'','จำนวนนักเรียน':Number(data.students)||0,'จำนวนครู':Number(data.teachers)||0,'จำนวนอื่นๆ':Number(data.others)||0,'สถานะ':STATUS.PENDING,'รถที่จัด':'','ผู้บันทึก':data.recordedBy||'','หมายเหตุ':data.note||''};
    map[REQ_DRIVER_NAME_COL_]=data.requestedDriver;map[REQ_PHONE_COL_]=data.requesterPhone;
    headers.forEach(function(h,i){if(Object.prototype.hasOwnProperty.call(map,h))row[i]=map[h];});sh.appendRow(row);
    var phoneIdx=headers.indexOf(REQ_PHONE_COL_);
    if(phoneIdx>=0&&data.requesterPhone)sh.getRange(sh.getLastRow(),phoneIdx+1).setNumberFormat('@').setValue(data.requesterPhone); // บังคับเป็นข้อความ เลข 0 นำหน้าไม่หาย
    appendAuditLog_(adminSession?'CREATE_BY_ADMIN':'PUBLIC_BOOKING_SUBMITTED',id,data.recordedBy,'',STATUS.PENDING,'',{type:adminSession?'CREATE_BY_ADMIN':'PUBLIC_BOOKING_SUBMITTED',requestId:id,submittedName:data.name,destination:data.destination});
    return {id:id,ok:true};
  }finally{lock.releaseLock();}
}
function updateRequestStatus(id,status,vehiclesCsv,recordedBy,note,adminToken,driver){
  var actingAdmin=requireAdminSession_(adminToken); recordedBy=actingAdmin.account;
  if(Object.keys(STATUS).map(function(k){return STATUS[k];}).indexOf(String(status))<0) throw new Error('สถานะที่ส่งมาไม่ถูกต้อง');
  if(String(status)===STATUS.ASSIGNED && !String(vehiclesCsv||'').trim()) throw new Error('ต้องเลือกอย่างน้อย 1 คันก่อนเปลี่ยนสถานะเป็นจัดรถแล้ว');
  var lock=LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var sh=sheet_(SHEETS.REQUESTS),headers=sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0],rows=rowsToObjects_(sh),target=rows.find(function(r){return String(r.id)===String(id);});
    if(!target)throw new Error('ไม่พบคำขอรหัส: '+id);
    function col(n){var i=headers.indexOf(n);if(i<0)throw new Error('ไม่พบคอลัมน์ '+n+' ในชีต Requests');return i+1;}
    var driverToSet=null;
    if(driver!==undefined&&driver!==null){
      driver=String(driver).trim();
      if(driver){
        if(getDriverNames_().indexOf(driver)<0)throw new Error('ไม่พบพนักงานขับรถ "'+driver+'" ในชีต Drivers');
        if([STATUS.APPROVED,STATUS.ASSIGNED,STATUS.IN_USE].indexOf(String(status))>-1){
          var hit=findDriverConflict_(rows,target,driver);
          if(hit)throw new Error('พนักงานขับรถ '+driver+' ถูกจัดให้ขับรถแล้วใน'+(hit.range.d1===hit.range.d2?thaiDateText_(hit.range.d1)+' เวลา '+hit.range.t1+' - '+hit.range.t2+' น.':'ตั้งแต่'+thaiDateText_(hit.range.d1)+' เวลา '+hit.range.t1+' น. ถึง'+thaiDateText_(hit.range.d2)+' เวลา '+hit.range.t2+' น.')+' (รายการของ '+String(hit.row['ชื่อ-นามสกุล']||'-')+') กรุณาเลือกพนักงานขับรถรายอื่น หรือเปลี่ยนคนขับของรายการก่อนหน้า');
        }
      }
      driverToSet=driver;
    }
    sh.getRange(target._row,col('สถานะ')).setValue(status);
    if(vehiclesCsv!==undefined&&vehiclesCsv!==null)sh.getRange(target._row,col('รถที่จัด')).setValue(vehiclesCsv);
    if(driverToSet!==null){
      var dci=headers.indexOf(DRIVER_COL_);
      if(dci<0){dci=headers.length;sh.getRange(1,dci+1).setValue(DRIVER_COL_);headers.push(DRIVER_COL_);}
      sh.getRange(target._row,dci+1).setValue(driverToSet);
    }
    if(recordedBy)sh.getRange(target._row,col('ผู้บันทึก')).setValue(recordedBy);
    if(note!==undefined&&note!==null)sh.getRange(target._row,col('หมายเหตุ')).setValue(note);
    return {ok:true};
  } finally {lock.releaseLock();}
}
function forecastVehicles(students,teachers,others,adminToken){requireAdminSession_(adminToken);var vehicles=getVehicles(adminToken).sort(function(a,b){return Number(b['ความจุ'])-Number(a['ความจุ']);}),groups=[{label:'นักเรียน',count:Number(students)||0},{label:'ครู',count:Number(teachers)||0},{label:'อื่นๆ',count:Number(others)||0}].filter(function(g){return g.count>0;}),plan=[],cautions=[],i=0,current=vehicles[0],remain=current?Number(current['ความจุ']):0,open=null;groups.forEach(function(g){var left=g.count;while(left>0&&current){var take=Math.min(left,remain);if(!open||open.vehicle!==current['ชื่อรถ']){open={vehicle:current['ชื่อรถ'],count:0,detail:[]};plan.push(open);}open.count+=take;open.detail.push(g.label+' '+take+' คน');left-=take;remain-=take;if(remain<=0){current=vehicles[++i];remain=current?Number(current['ความจุ']):0;open=null;}}if(left>0)cautions.push('รถในกองรถไม่พอสำหรับ'+g.label+'อีก '+left+' คน — ต้องพิจารณาวิ่งเพิ่มเที่ยว หรือหาทางเลือกอื่น');});plan.forEach(function(p){var v=vehicles.find(function(x){return x['ชื่อรถ']===p.vehicle;});if(v&&Number(v['ความจุ'])>=13&&p.count<=Number(v['ความจุ'])*.25)cautions.push(p.vehicle+' บรรทุกแค่ '+p.count+' คน (จุได้ '+v['ความจุ']+') — ลองย้ายไปรวมกับคันอื่นที่ยังมีที่ว่างแทนได้');});if(plan.filter(function(p){return p.vehicle.indexOf('หกล้อ')>-1;}).length>=2)cautions.push('ถ้าระยะทางใกล้พอให้รถหกล้อวิ่ง 2 เที่ยวทันเวลา อาจลดจำนวนรถที่ใช้ได้ — ควรโทรถามครูผู้ขอเรื่องระยะเวลาก่อนตัดสินใจ');return {plan:plan,cautions:cautions};}

function getAuditSheet_(){var ss=ss_(),sh=ss.getSheetByName(AUDIT_SHEET_NAME);if(!sh){sh=ss.insertSheet(AUDIT_SHEET_NAME);sh.appendRow(['logId','timestamp','action','requestId','admin','oldStatus','newStatus','vehicles','detail']);sh.setFrozenRows(1);}return sh;}
function appendAuditLog_(action,requestId,admin,oldStatus,newStatus,vehicles,detail){var sh=getAuditSheet_(),logId='LOG-'+Utilities.getUuid().substring(0,8).toUpperCase();sh.appendRow([logId,new Date(),action||'',requestId||'',admin||'',oldStatus||'',newStatus||'',vehicles||'',typeof detail==='string'?detail:JSON.stringify(detail||{})]);return logId;}
function findRequestRowById_(id){var sh=sheet_(SHEETS.REQUESTS),values=sh.getDataRange().getValues();if(values.length<2)return null;var headers=values[0],idx=headers.indexOf('id');if(idx<0)throw new Error('ไม่พบคอลัมน์ id ในชีต Requests');for(var i=1;i<values.length;i++)if(String(values[i][idx])===String(id)){var obj={};headers.forEach(function(h,j){obj[h]=values[i][j];});return {sheet:sh,row:i+1,headers:headers,values:values[i],object:obj};}return null;}
function findLatestMatchingRequest_(payload){var sh=sheet_(SHEETS.REQUESTS),values=sh.getDataRange().getValues();if(values.length<2)return null;var headers=values[0],idx={};headers.forEach(function(h,i){idx[h]=i;});var best=null,bestTs=0;for(var i=1;i<values.length;i++){var row=values[i];if(String(row[idx['ชื่อ-นามสกุล']]||'')!==String(payload.name||'')||String(row[idx['ปลายทาง']]||'')!==String(payload.destination||'')||!sameDateValue_(row[idx['วันที่ไป']],payload.dateGo)||normalizeTimeValue_(row[idx['เวลาไป']])!==normalizeTimeValue_(payload.timeGo))continue;var t=row[idx.timestamp],ts=t instanceof Date?t.getTime():new Date(t).getTime();if(ts>=bestTs){bestTs=ts;var obj={};headers.forEach(function(h,j){obj[h]=row[j];});best={row:i+1,object:obj};}}return best;}
function saveRequestWithAudit(payload,adminToken){
  var actingAdmin=requireAdminSession_(adminToken);
  payload=payload||{};
  payload.recordedBy=actingAdmin.account;
  // saveRequest owns the write lock and writes its own CREATE_BY_ADMIN audit entry.
  // Do not acquire the same script lock here; nested locking can time out.
  var result=saveRequest(payload,adminToken);
  appendAuditLog_('CREATE',result.id,actingAdmin.account,'',STATUS.PENDING,'',{type:'CREATE',savedRequestId:result.id});
  return result;
}
function updateRequestStatusWithAudit(id,status,vehicles,recordedBy,note,adminToken,driver){
  var actingAdmin=requireAdminSession_(adminToken); recordedBy=actingAdmin.account;
  var before=findRequestRowById_(id); if(!before)throw new Error('ไม่พบรายการคำขอ: '+id);
  var result=updateRequestStatus(id,status,vehicles,recordedBy,note,adminToken,driver),after=findRequestRowById_(id);
  appendAuditLog_('UPDATE',id,recordedBy||'',before.object['สถานะ']||'',status||'',vehicles||'',{type:'UPDATE',before:before.object,after:after?after.object:{status:status,vehicles:vehicles},note:note||'',previousVehicles:before.object['รถที่จัด']||'',previousDriver:before.object[DRIVER_COL_]||'',driver:after?(after.object[DRIVER_COL_]||''):''}); return result;
}
function deleteRequest(id,adminToken){
  var actingAdmin=requireAdminSession_(adminToken); var admin=actingAdmin.account;
  var lock=LockService.getScriptLock();lock.waitLock(10000);
  try{var found=findRequestRowById_(id);if(!found)throw new Error('ไม่พบรายการคำขอ: '+id);appendAuditLog_('DELETE',id,admin||'',found.object['สถานะ']||'','ลบรายการ',found.object['รถที่จัด']||'',{type:'DELETE',deletedRequest:found.object});found.sheet.deleteRow(found.row);return true;}
  finally{lock.releaseLock();}
}
function getAuditLogs(adminToken){requireAdminSession_(adminToken);var sh=getAuditSheet_(),values=sh.getDataRange().getValues();if(values.length<2)return [];var headers=values[0],out=[];for(var i=values.length-1;i>=1;i--){var row=values[i],o={};headers.forEach(function(h,j){o[h]=row[j];});out.push({logId:o.logId||'',timestamp:o.timestamp instanceof Date?o.timestamp.toISOString():String(o.timestamp||''),action:o.action||'',requestId:o.requestId||'',admin:o.admin||'',oldStatus:o.oldStatus||'',newStatus:o.newStatus||'',vehicles:o.vehicles||'',detail:o.detail||''});}return out;}

var CONFLICT_ACK_SHEET='ConflictAcknowledgements';
function getConflictAckSheet_(){
  var ss=ss_(),sh=ss.getSheetByName(CONFLICT_ACK_SHEET);
  if(!sh){sh=ss.insertSheet(CONFLICT_ACK_SHEET);sh.appendRow(['conflictKey','timestamp','requestId','otherRequestId','vehicles','admin']);sh.setFrozenRows(1);}
  return sh;
}
function makeConflictKey_(id1,id2,vehicleNames){
  var ids=[String(id1||''),String(id2||'')].sort();
  var names=(Array.isArray(vehicleNames)?vehicleNames:[]).map(function(v){return String(v||'').trim();}).filter(Boolean).sort();
  return ids[0]+'::'+ids[1]+'::'+names.join(',');
}
function getConflictAcknowledgements(adminToken){requireAdminSession_(adminToken);
  var sh=getConflictAckSheet_(),values=sh.getDataRange().getValues();
  if(values.length<2)return [];
  var headers=values[0],idx={};headers.forEach(function(h,i){idx[h]=i;});
  var seen={};
  for(var i=1;i<values.length;i++){var row=values[i],key=String(row[idx.conflictKey]||'');if(key)seen[key]={conflictKey:key,timestamp:row[idx.timestamp] instanceof Date?row[idx.timestamp].toISOString():String(row[idx.timestamp]||''),requestId:String(row[idx.requestId]||''),otherRequestId:String(row[idx.otherRequestId]||''),vehicles:String(row[idx.vehicles]||''),admin:String(row[idx.admin]||'')};}
  return Object.keys(seen).map(function(k){return seen[k];});
}
function acknowledgeConflict(requestId,otherRequestId,vehicleNames,adminToken){
  var actingAdmin=requireAdminSession_(adminToken); var admin=actingAdmin.account;
  requestId=String(requestId||'').trim();otherRequestId=String(otherRequestId||'').trim();
  if(!requestId||!otherRequestId||requestId===otherRequestId)throw new Error('ข้อมูลรายการรถซ้ำซ้อนไม่ถูกต้อง');
  if(!Array.isArray(vehicleNames)||!vehicleNames.length)throw new Error('ไม่พบชื่อรถที่ซ้ำซ้อน');
  var a=findRequestRowById_(requestId),b=findRequestRowById_(otherRequestId);
  if(!a||!b)throw new Error('ไม่พบคำขออย่างน้อยหนึ่งรายการ');
  var key=makeConflictKey_(requestId,otherRequestId,vehicleNames),lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    var sh=getConflictAckSheet_(),values=sh.getDataRange().getValues();
    for(var i=1;i<values.length;i++)if(String(values[i][0])===key)return {ok:true,alreadyAcknowledged:true,conflictKey:key};
    sh.appendRow([key,new Date(),requestId,otherRequestId,vehicleNames.join(', '),String(admin||'').trim()]);
    appendAuditLog_('ACK_CONFLICT',requestId,String(admin||'').trim(),a.object['สถานะ']||'',b.object['สถานะ']||'',vehicleNames.join(', '),{type:'ACK_CONFLICT',requestId:requestId,otherRequestId:otherRequestId,vehicles:vehicleNames,acknowledged:true});
    return {ok:true,conflictKey:key};
  }finally{lock.releaseLock();}
}

function sameDateValue_(sheetValue,payloadValue){if(!sheetValue||!payloadValue)return false;var target=String(payloadValue).substring(0,10);if(sheetValue instanceof Date)return Utilities.formatDate(sheetValue,Session.getScriptTimeZone(),'yyyy-MM-dd')===target;var s=String(sheetValue).trim();return /^\d{4}-\d{2}-\d{2}/.test(s)?s.substring(0,10)===target:s===target;}
function normalizeTimeValue_(value){if(value instanceof Date)return Utilities.formatDate(value,Session.getScriptTimeZone(),'HH:mm');var s=String(value||'').trim().replace('.',':'),m=s.match(/^(\d{1,2}):(\d{1,2})/);if(!m)return s;return String(parseInt(m[1],10)).padStart(2,'0')+':'+String(parseInt(m[2],10)).padStart(2,'0');}

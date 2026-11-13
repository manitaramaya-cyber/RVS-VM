var ADMIN_KEY='rav-fleet-x9k2m7'; // ใช้เลือกหน้าเว็บเท่านั้น ไม่ใช่การยืนยันสิทธิ์ Admin
var SHEETS={STAFF:'Staff',REQUESTS:'Requests',VEHICLES:'Vehicles',DRIVERS:'Drivers'};
var APP_VERSION='V1.3.0'; // Bulk Delete + Bulk Complete + HH.MM time input
var REQ_DRIVER_NAME_COL_='ชื่อผู้ขับรถที่ผู้ขอระบุ'; // V1.2.9: ชื่อผู้ขับรถที่ผู้ขอใช้รถระบุเอง (แยกจาก DRIVER_COL_ ที่ Admin จัดสรร ห้ามเขียนทับกัน)
var REQ_PHONE_COL_='เบอร์โทรผู้ขอใช้รถ'; // V1.2.9: เบอร์ติดต่อผู้ขอใช้รถ (เฉพาะ Admin เห็น ไม่ส่งออกใน getBookingsForMonth)
var DRIVER_COL_='คนขับที่จัด'; // คอลัมน์ในชีต Requests (ถ้ายังไม่มี ระบบจะสร้างให้อัตโนมัติเมื่อบันทึกคนขับครั้งแรก)
var DRIVER_FROM_COL_='คนขับเริ่มปฏิบัติหน้าที่'; // V1.2.9 (9 พ.ย. 69): วัน-เวลาที่คนขับที่ Admin จัดสรรเริ่มปฏิบัติหน้าที่ (เก็บเป็นข้อความ yyyy-MM-dd HH:mm)
var DRIVER_TO_COL_='คนขับสิ้นสุดปฏิบัติหน้าที่'; // V1.2.9 (9 พ.ย. 69): วัน-เวลาที่คนขับสิ้นสุดการปฏิบัติหน้าที่ — ใช้ตรวจคนขับซ้ำซ้อนตามช่วงเวลานี้
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
// LINE Messaging API Webhook: ใช้ shared key ใน query string เพราะ Apps Script Web App อ่าน request headers ไม่ได้
function doPost(e){
  try{
    var props=PropertiesService.getScriptProperties();
    var expected=props.getProperty('LINE_WEBHOOK_KEY');
    var supplied=e&&e.parameter&&String(e.parameter.hook||'');
    if(!expected||!supplied||supplied!==expected)return ContentService.createTextOutput(JSON.stringify({ok:false})).setMimeType(ContentService.MimeType.JSON);
    var raw=e&&e.postData&&e.postData.contents?e.postData.contents:'{}',body=JSON.parse(raw),events=Array.isArray(body.events)?body.events:[];
    var captured='';
    events.forEach(function(ev){
      var source=ev&&ev.source;
      if(source&&source.type==='group'&&source.groupId)captured=String(source.groupId);
    });
    if(captured){
      props.setProperty('LINE_GROUP_ID',captured);
      props.setProperty('LINE_WEBHOOK_LAST_EVENT_AT',Utilities.formatDate(new Date(),'Asia/Bangkok','yyyy-MM-dd HH:mm:ss'));
    }
    return ContentService.createTextOutput(JSON.stringify({ok:true,groupCaptured:!!captured})).setMimeType(ContentService.MimeType.JSON);
  }catch(err){
    // ตอบ 200 เพื่อไม่ให้ LINE retry วนไม่สิ้นสุด; รายละเอียดเก็บใน execution log
    console.error('LINE webhook error: '+String(err&&err.stack||err));
    return ContentService.createTextOutput(JSON.stringify({ok:false})).setMimeType(ContentService.MimeType.JSON);
  }
}
// รันครั้งเดียวเพื่อสร้าง shared key สำหรับ Webhook URL; ไม่เกี่ยวกับ Channel Access Token
function createLineWebhookKey(){
  var props=PropertiesService.getScriptProperties(),key=props.getProperty('LINE_WEBHOOK_KEY');
  if(!key){key=Utilities.getUuid().replace(/-/g,'')+Utilities.getUuid().replace(/-/g,'');props.setProperty('LINE_WEBHOOK_KEY',key);}
  return key;
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
  [REQ_DRIVER_NAME_COL_,REQ_PHONE_COL_,DRIVER_FROM_COL_,DRIVER_TO_COL_].forEach(function(name){
    if(headers.indexOf(name)>=0)return;
    var need=headers.length+1;
    if(sh.getMaxColumns()<need)sh.insertColumnsAfter(sh.getMaxColumns(),need-sh.getMaxColumns());
    sh.getRange(1,need).setValue(name);
    if(name===REQ_PHONE_COL_||name===DRIVER_FROM_COL_||name===DRIVER_TO_COL_)sh.getRange(2,need,Math.max(sh.getMaxRows()-1,1),1).setNumberFormat('@'); // เก็บเป็นข้อความ กันเลข 0 นำหน้าหาย
    headers.push(name);
  });
  return headers;
}
function cleanPhone_(v){return String(v==null?'':v).trim().replace(/[^\d+\-\s()]/g,'').slice(0,30);}
function formatPhone_(v){var s=String(v==null?'':v).trim();return /^\d{9}$/.test(s)?'0'+s:s;} // ข้อมูลที่ Sheets แปลงเป็นตัวเลขจนเลข 0 นำหน้าหาย
function requestToClient_(r){
  return {id:String(r.id||''),staffId:String(r['รหัสบุคลากร']||''),name:String(r['ชื่อ-นามสกุล']||''),position:String(r['ตำแหน่ง']||''),department:String(r['สังกัด']||''),destination:String(r['ปลายทาง']||''),purpose:String(r['วัตถุประสงค์']||''),dateGo:formatDate_(r['วันที่ไป']),timeGo:formatTime_(r['เวลาไป']),dateBack:formatDate_(r['วันที่กลับ']),timeBack:formatTime_(r['เวลากลับ']),needDriver:String(r['ต้องการคนขับ']||''),companionCount:Number(r['จำนวนผู้ร่วมเดินทาง'])||0,companionNames:String(r['รายชื่อผู้ร่วมเดินทาง']||''),isLarge:String(r['ทริปใหญ่']||''),students:Number(r['จำนวนนักเรียน'])||0,teachers:Number(r['จำนวนครู'])||0,others:Number(r['จำนวนอื่นๆ'])||0,status:String(r['สถานะ']||''),vehicles:String(r['รถที่จัด']||''),driver:String(r[DRIVER_COL_]||''),driverFrom:dutyValue_(r[DRIVER_FROM_COL_]),driverTo:dutyValue_(r[DRIVER_TO_COL_]),requestedDriver:String(r[REQ_DRIVER_NAME_COL_]||''),requesterPhone:formatPhone_(r[REQ_PHONE_COL_]),recordedBy:String(r['ผู้บันทึก']||''),note:String(r['หมายเหตุ']||'')};
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
var DAILY_REPORT_EXCLUDED_STATUSES_=[STATUS.CANCELLED,STATUS.REJECTED];
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
  // รายงานทุกคำขอของวันที่เลือก ยกเว้นยกเลิก/ปฏิเสธ แม้ยังไม่อนุมัติหรือยังจัดรถ/คนขับไม่ครบ
  var vehRows=rowsToObjects_(sheet_(SHEETS.VEHICLES));
  var cand=rowsToObjects_(sheet_(SHEETS.REQUESTS)).map(requestToClient_).filter(function(r){
    return r.dateGo===dateKey&&DAILY_REPORT_EXCLUDED_STATUSES_.indexOf(r.status)<0;
  }).sort(function(a,b){return String(a.timeGo).localeCompare(String(b.timeGo));});
  var warnings=[],blocks=[];
  cand.forEach(function(r){
    var vlist=String(r.vehicles||'').split(',').map(function(x){return vehicleLabel_(x,vehRows);}).filter(Boolean);
    var drv=reportDriverName_(r),who=r.name+' ('+(r.timeGo||'-')+' น.)';
    var total=(Number(r.students)||0)+(Number(r.teachers)||0)+(Number(r.others)||0);if(total<=0)total=Number(r.companionCount)||0;
    if(!total)warnings.push(who+': ไม่ระบุจำนวนผู้ร่วมเดินทาง (รายงานเป็น 0 คน)');
    var purpose=String(r.purpose||'').trim(),dest=String(r.destination||'').trim();
    var what=purpose+((dest&&purpose.indexOf(dest)<0)?' ณ '+dest:'');
    var lines=['เวลา '+(r.timeGo||'-')+' น.'];
    if(vlist.length)vlist.forEach(function(v){lines.push('🚐'+v);});
    else lines.push('🚐รอจัดรถ');
    if(drv)lines.push('🙎🏻ผู้ขับรถ  '+drv);
    else if(String(r.needDriver||'').trim()==='ต้องการ')lines.push('🙎🏻ผู้ขับรถ  รอจัดผู้ขับรถ');
    else lines.push('🙎🏻ผู้ขับรถ  ไม่ต้องการผู้ขับรถจากโรงเรียน');
    lines.push('');lines.push('-'+what);lines.push('ผู้ร่วมเดินทาง '+total+' คน');
    blocks.push(lines.join('\n'));
  });
  var text=blocks.length?('แจ้งการใช้รถโรงเรียน\n'+thaiLongDate_(dateKey)+'\n\n'+blocks.join('\n\n')+'\n\n🙏🏻ขอบคุณครับ🙏🏻'):'';
  return {dateKey:dateKey,dateText:thaiLongDate_(dateKey),count:blocks.length,skippedCount:0,warnings:warnings,blocks:blocks,text:text};
}
function lineConfigured_(){var p=PropertiesService.getScriptProperties();return !!(p.getProperty(LINE_TOKEN_PROP_)&&p.getProperty(LINE_GROUP_PROP_));}
function autoTriggerOn_(){try{return ScriptApp.getProjectTriggers().some(function(t){return t.getHandlerFunction()==='vehicleLine24hJob';});}catch(e){return null;}}
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
// ทดสอบส่งข้อความไปยัง LINE กลุ่มที่ตั้งค่าไว้ใน Script Properties
// เรียกฟังก์ชันนี้จาก Apps Script Editor เพื่อทดสอบการเชื่อมต่อ
function TestLineGroupMessage(){
  var message='ทดสอบการเชื่อมต่อ LINE กลุ่ม RVS-VM\nระบบสามารถส่งข้อความเข้ากลุ่มได้แล้ว\nเวลา: '+Utilities.formatDate(new Date(),'Asia/Bangkok','dd/MM/yyyy HH:mm:ss');
  sendLineText_(message);
  Logger.log('ส่งข้อความทดสอบไปยัง LINE Group สำเร็จ');
  return 'ส่งข้อความทดสอบไปยัง LINE Group สำเร็จ';
}
// Admin กดส่งเอง (ส่งข้อความที่แก้ไขแล้วในช่องได้; ถ้าว่างใช้ข้อความที่ระบบสร้าง)
function sendDailyReportToLine(dateKey,text,adminToken){
  var admin=requireAdminSession_(adminToken);
  dateKey=String(dateKey||'').trim()||todayKey_();
  text=String(text||'').trim()||buildDailyReport_(dateKey).text;
  if(!text)throw new Error('ไม่มีรายการใช้รถในวันที่เลือก จึงไม่ส่งข้อความ');
  sendLineText_(text);
  appendAuditLog_('DAILY_REPORT_SENT','',admin.account,'','','',{type:'DAILY_REPORT_SENT',date:dateKey,length:text.length});
  return {ok:true};
}
// ===== แจ้งเตือน LINE ล่วงหน้า 24 ชั่วโมงก่อนใช้รถ (ตรวจสอบทุก 5 นาที) =====
var VEHICLE_LINE_LOG_SHEET_='VehicleLineNotifications';
var VEHICLE_LINE_LOG_HEADERS_=['NotificationKey','RequestID','TravelDate','ScheduledAt','DepartureAt','Signature','Status','SentAt','ErrorMessage','UpdatedAt'];
var VEHICLE_LINE_ACTIVE_STATUSES_=[STATUS.APPROVED,STATUS.ASSIGNED];
function vehicleLineLogSheet_(){
  var ss=ss_(),sh=ss.getSheetByName(VEHICLE_LINE_LOG_SHEET_);
  if(!sh){sh=ss.insertSheet(VEHICLE_LINE_LOG_SHEET_);sh.getRange(1,1,1,VEHICLE_LINE_LOG_HEADERS_.length).setValues([VEHICLE_LINE_LOG_HEADERS_]);sh.setFrozenRows(1);}
  return sh;
}
function vehicleTravelDates_(dateGo,dateBack){
  var start=String(dateGo||''),end=String(dateBack||dateGo||'');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(start)||!/^\d{4}-\d{2}-\d{2}$/.test(end)||end<start)return [];
  var a=start.split('-').map(Number),b=end.split('-').map(Number),cur=new Date(Date.UTC(a[0],a[1]-1,a[2])),last=new Date(Date.UTC(b[0],b[1]-1,b[2])),out=[];
  for(var i=0;i<370&&cur<=last;i++){out.push(Utilities.formatDate(cur,'UTC','yyyy-MM-dd'));cur.setUTCDate(cur.getUTCDate()+1);}
  return out;
}
function vehicleDepartureAt_(dateKey,timeText){
  var m=String(timeText||'').trim().match(/^(\d{1,2}):(\d{2})/);
  if(!m)return null;var h=Number(m[1]),mi=Number(m[2]);if(h>23||mi>59)return null;
  var p=dateKey.split('-').map(Number);return new Date(Date.UTC(p[0],p[1]-1,p[2],h-7,mi,0));
}
function vehicleLineMessage_(r,dateKey,corrected){
  // ใช้รูปแบบเดียวกับ buildDailyReport_() แต่แสดงเฉพาะคำขอที่ถึงกำหนดแจ้งเตือน
  var vehRows=rowsToObjects_(sheet_(SHEETS.VEHICLES));
  var vlist=String(r.vehicles||'').split(',').map(function(x){return vehicleLabel_(x,vehRows);}).filter(Boolean);
  var drv=reportDriverName_(r);
  var total=(Number(r.students)||0)+(Number(r.teachers)||0)+(Number(r.others)||0);
  if(total<=0)total=Number(r.companionCount)||0;
  var purpose=String(r.purpose||'').trim(),dest=String(r.destination||'').trim();
  var what=purpose+((dest&&purpose.indexOf(dest)<0)?' ณ '+dest:'');
  var lines=['เวลา '+(r.timeGo||'-')+' น.'];
  if(vlist.length)vlist.forEach(function(v){lines.push('🚐'+v);});
  else lines.push('🚐รอจัดรถ');
  if(drv)lines.push('🙎🏻ผู้ขับรถ  '+drv);
  else if(String(r.needDriver||'').trim()==='ต้องการ')lines.push('🙎🏻ผู้ขับรถ  รอจัดผู้ขับรถ');
  else lines.push('🙎🏻ผู้ขับรถ  ไม่ต้องการผู้ขับรถจากโรงเรียน');
  lines.push('');lines.push('-'+what);lines.push('ผู้ร่วมเดินทาง '+total+' คน');
  var heading='แจ้งการใช้รถโรงเรียน';
  return heading+'\n'+thaiLongDate_(dateKey)+'\n\n'+lines.join('\n')+'\n\n🙏🏻ขอบคุณครับ🙏🏻';
}
function vehicleLineSignature_(r,dateKey){
  return sha256Hex_(JSON.stringify({date:dateKey,time:r.timeGo,name:r.name,destination:r.destination,purpose:r.purpose,vehicles:r.vehicles,driver:r.driver,requestedDriver:r.requestedDriver,status:r.status,students:r.students,teachers:r.teachers,others:r.others,needDriver:r.needDriver}));
}
function vehicleLineUpsertLog_(sh,row,values){
  if(row)sh.getRange(row,1,1,VEHICLE_LINE_LOG_HEADERS_.length).setValues([values]);
  else{row=sh.getLastRow()+1;sh.getRange(row,1,1,VEHICLE_LINE_LOG_HEADERS_.length).setValues([values]);}
  return row;
}
// Trigger: ตรวจทุก 5 นาที และส่งแต่ละคำขอเมื่อถึงเวลา 24 ชั่วโมงก่อนออกเดินทาง
function vehicleLine24hJob(){
  if(!lineConfigured_())return;
  var lock=LockService.getScriptLock();if(!lock.tryLock(10000))return;
  try{
    var now=new Date(),sh=vehicleLineLogSheet_(),logs=rowsToObjects_(sh),byKey={};
    logs.forEach(function(x){byKey[String(x.NotificationKey||'')]=x;});
    var requests=rowsToObjects_(sheet_(SHEETS.REQUESTS)).map(requestToClient_),requestById={};
    requests.forEach(function(r){requestById[r.id]=r;});
    logs.forEach(function(log){
      if(String(log.Status)!=='Sent')return;
      var current=requestById[String(log.RequestID||'')];
      if(current&&[STATUS.CANCELLED,STATUS.REJECTED].indexOf(current.status)>=0){
        try{
          sendLineText_('❌ ยกเลิกการใช้รถโรงเรียน\n'+thaiLongDate_(String(log.TravelDate||''))+'\nรหัสคำขอ: '+current.id+'\nผู้ขอใช้รถ: '+current.name+'\nปลายทาง: '+current.destination);
          sh.getRange(log._row,7).setValue('Cancelled');sh.getRange(log._row,10).setValue(nowText_());
        }catch(err){sh.getRange(log._row,9).setValue(String(err&&err.message||err));}
      }
    });
    requests.forEach(function(r){
      if(VEHICLE_LINE_ACTIVE_STATUSES_.indexOf(r.status)<0||!r.id)return;
      vehicleTravelDates_(r.dateGo,r.dateBack).forEach(function(dateKey){
        var departure=vehicleDepartureAt_(dateKey,r.timeGo);if(!departure)return;
        var notifyAt=new Date(departure.getTime()-24*60*60*1000);if(now>=departure)return;
        var key=r.id+'|'+dateKey,signature=vehicleLineSignature_(r,dateKey),old=byKey[key],row=old?old._row:null;
        if(old&&String(old.Status)==='Sent'&&String(old.Signature)===signature)return;
        if(now<notifyAt&&!(old&&String(old.Status)==='Sent'))return;
        var isCorrection=!!(old&&String(old.Status)==='Sent'&&String(old.Signature)!==signature);
        var scheduledText=Utilities.formatDate(notifyAt,'Asia/Bangkok','yyyy-MM-dd HH:mm:ss'),departureText=Utilities.formatDate(departure,'Asia/Bangkok','yyyy-MM-dd HH:mm:ss');
        try{
          sendLineText_(vehicleLineMessage_(r,dateKey,isCorrection));
          var vals=[key,r.id,dateKey,scheduledText,departureText,signature,'Sent',nowText_(),'',nowText_()];
          var savedRow=vehicleLineUpsertLog_(sh,row,vals);byKey[key]={NotificationKey:key,RequestID:r.id,TravelDate:dateKey,Signature:signature,Status:'Sent',_row:savedRow};
          try{appendAuditLog_(isCorrection?'VEHICLE_LINE_CORRECTION':'VEHICLE_LINE_24H',r.id,'system','','','',{type:'VEHICLE_LINE_24H',travelDate:dateKey,departureAt:departureText,correction:isCorrection});}catch(e){}
        }catch(err){
          var valsFail=[key,r.id,dateKey,scheduledText,departureText,signature,'Failed',old?String(old.SentAt||''):'',String(err&&err.message||err).slice(0,500),nowText_()];
          vehicleLineUpsertLog_(sh,row,valsFail);
        }
      });
    });
  }finally{lock.releaseLock();}
}
// รันครั้งเดียวจาก Apps Script Editor: ยกเลิก Trigger 05:30 เดิม แล้วติดตั้งตัวตรวจทุก 5 นาที
function installVehicle24hLineTrigger(){
  removeDailyLineTrigger();
  ScriptApp.getProjectTriggers().forEach(function(t){if(t.getHandlerFunction()==='vehicleLine24hJob')ScriptApp.deleteTrigger(t);});
  ScriptApp.newTrigger('vehicleLine24hJob').timeBased().everyMinutes(5).create();
  return 'เปิดระบบตรวจสอบทุก 5 นาที: แจ้งเตือนก่อนใช้รถ 24 ชั่วโมง (ยกเลิก Trigger 05:30 เดิมแล้ว)';
}
function installDailyLineTrigger(){return installVehicle24hLineTrigger();}
function removeDailyLineTrigger(){
  ScriptApp.getProjectTriggers().forEach(function(t){if(['dailyLineReportJob','vehicleLine24hJob'].indexOf(t.getHandlerFunction())>=0)ScriptApp.deleteTrigger(t);});
  return 'ยกเลิก Trigger แจ้งเตือน LINE อัตโนมัติแล้ว';
}
// ===== V1.2.9: แบบประเมินความพึงพอใจ (เก็บในชีต Feedback สร้างให้อัตโนมัติ) =====
var FEEDBACK_SHEET_NAME='Feedback';
var FEEDBACK_LABELS_={5:'ยอดเยี่ยม',4:'ดีเลิศ',3:'ดี',2:'ปานกลาง',1:'กำลังพัฒนา'};
function getFeedbackSheet_(){
  var ss=ss_(),sh=ss.getSheetByName(FEEDBACK_SHEET_NAME);
  if(!sh){sh=ss.insertSheet(FEEDBACK_SHEET_NAME);sh.appendRow(['รหัส','เวลา','คะแนน (1-5)','ระดับ','ข้อเสนอแนะ','ชื่อผู้เสนอแนะ','เวอร์ชันระบบ']);sh.setFrozenRows(1);}
  return sh;
}
// เรียกจากหน้า Calendar (สาธารณะ ไม่ต้องล็อกอิน): ชื่อและข้อเสนอแนะเป็นตัวเลือก ไม่บังคับ
function submitFeedback(data){
  data=data||{};
  var rating=Number(data.rating);
  if(!(rating>=1&&rating<=5)||Math.floor(rating)!==rating)throw new Error('กรุณาเลือกระดับความพึงพอใจ (1-5)');
  var comment=String(data.comment==null?'':data.comment).trim().slice(0,1000),name=String(data.name==null?'':data.name).trim().slice(0,100);
  var cache=CacheService.getScriptCache(),n=Number(cache.get('FB_RATE')||0);
  if(n>=120)throw new Error('มีการส่งแบบประเมินถี่เกินไป กรุณาลองใหม่ภายหลัง');
  cache.put('FB_RATE',String(n+1),3600);
  var lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    var sh=getFeedbackSheet_(),r=sh.getLastRow()+1,id='FB-'+Utilities.getUuid().substring(0,8).toUpperCase();
    sh.getRange(r,5,1,2).setNumberFormat('@'); // บังคับเป็นข้อความ กันข้อความที่ขึ้นต้นด้วย = + - @ ถูกตีความเป็นสูตร
    sh.getRange(r,1,1,7).setValues([[id,new Date(),rating,FEEDBACK_LABELS_[rating],comment,name,APP_VERSION]]);
  }finally{lock.releaseLock();}
  return {ok:true};
}
// อ่านอย่างเดียว: สรุปผลแบบประเมินความพึงพอใจให้แท็บ "ดูความพึงพอใจ" ใน Admin
function getFeedbackSummary(adminToken){
  requireAdminSession_(adminToken);
  var sh=ss_().getSheetByName(FEEDBACK_SHEET_NAME),counts={1:0,2:0,3:0,4:0,5:0},items=[];
  if(sh){
    rowsToObjects_(sh).forEach(function(r){
      var rating=Number(r['คะแนน (1-5)']);
      if(!(rating>=1&&rating<=5)||Math.floor(rating)!==rating)return;
      var t=r['เวลา'],tm=(t instanceof Date)?Utilities.formatDate(t,Session.getScriptTimeZone(),'yyyy-MM-dd HH:mm'):String(t||'');
      counts[rating]++;
      items.push({id:String(r['รหัส']||''),time:tm,rating:rating,label:FEEDBACK_LABELS_[rating],comment:String(r['ข้อเสนอแนะ']||''),name:String(r['ชื่อผู้เสนอแนะ']||'')});
    });
  }
  items.reverse(); // ใหม่สุดก่อน
  var total=items.length,sum=0;for(var k=1;k<=5;k++)sum+=k*counts[k];
  return {sheetExists:!!sh,total:total,average:total?sum/total:0,counts:counts,items:items.slice(0,500)};
}
// ===== V2.0.0: เอกสารสำคัญของรถ (พรบ. / ประกัน / ทะเบียน / ภาษี) + แจ้งเตือนวันหมดอายุ =====
// ชีตสร้างให้อัตโนมัติ: VehicleDocs (ข้อมูลปัจจุบัน 1 แถวต่อ รถ+ประเภท) และ VehicleDocHistory (ข้อมูลเก่าเมื่อต่ออายุ/เปลี่ยนไฟล์)
// ไฟล์ PDF เก็บในโฟลเดอร์ Google Drive ชื่อ "RVS-VM เอกสารรถ" ของบัญชีเจ้าของสคริปต์ (สร้างให้อัตโนมัติ)
var DOC_SHEET_NAME='VehicleDocs',DOC_HISTORY_SHEET_NAME='VehicleDocHistory';
var DOC_ALERT_DAYS_=30; // แจ้งเตือนล่วงหน้า (วัน)
var DOC_TYPES_=['พรบ.','ประกัน','ทะเบียน','ภาษี'];
var DOC_HEADERS_=['รหัส','ชื่อรถ','ประเภทเอกสาร','เลขที่เอกสาร','วันหมดอายุ','ไฟล์ PDF (Drive ID)','ชื่อไฟล์','หมายเหตุ','รับทราบวันหมดอายุ','รับทราบโดย','รับทราบเมื่อ','อัปเดตโดย','อัปเดตเมื่อ'];
var DOC_HISTORY_HEADERS_=['เวลา','ชื่อรถ','ประเภทเอกสาร','เลขที่เอกสาร (เดิม)','วันหมดอายุ (เดิม)','ไฟล์ PDF เดิม (Drive ID)','ชื่อไฟล์เดิม','หมายเหตุเดิม','ดำเนินการโดย','เหตุผล'];
var DOC_FOLDER_NAME_='RVS-VM เอกสารรถ';
var DOC_MAX_BYTES_=4*1024*1024;
function nowText_(){return Utilities.formatDate(new Date(),'Asia/Bangkok','yyyy-MM-dd HH:mm');}
function normDate_(v){
  if(v==null||v==='')return '';
  if(v instanceof Date)return Utilities.formatDate(v,'Asia/Bangkok','yyyy-MM-dd');
  var s=String(v).trim();if(/^\d{4}-\d{2}-\d{2}$/.test(s))return s;
  var d=new Date(s);return isNaN(d.getTime())?s:Utilities.formatDate(d,'Asia/Bangkok','yyyy-MM-dd');
}
function daysUntil_(dateKey){
  var m=String(dateKey||'').match(/^(\d{4})-(\d{2})-(\d{2})$/),t=todayKey_().match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if(!m||!t)return null;
  return Math.round((Date.UTC(+m[1],+m[2]-1,+m[3])-Date.UTC(+t[1],+t[2]-1,+t[3]))/86400000);
}
function getDocSheet_(name,headers,textCols){
  var ss=ss_(),sh=ss.getSheetByName(name);
  if(!sh){
    sh=ss.insertSheet(name);sh.appendRow(headers);sh.setFrozenRows(1);
    (textCols||[]).forEach(function(c){sh.getRange(1,c,sh.getMaxRows(),1).setNumberFormat('@');}); // วันที่เก็บเป็นข้อความ กันเลื่อนวัน/โซนเวลา
  }
  return sh;
}
function docSheet_(){return getDocSheet_(DOC_SHEET_NAME,DOC_HEADERS_,[5,9]);}
function docHistorySheet_(){return getDocSheet_(DOC_HISTORY_SHEET_NAME,DOC_HISTORY_HEADERS_,[5]);}
function readDocs_(){
  var sh=ss_().getSheetByName(DOC_SHEET_NAME);if(!sh)return [];
  return rowsToObjects_(sh).map(function(r){return {row:r._row,id:String(r['รหัส']||''),vehicle:String(r['ชื่อรถ']||''),type:String(r['ประเภทเอกสาร']||''),docNo:String(r['เลขที่เอกสาร']||''),expiry:normDate_(r['วันหมดอายุ']),fileId:String(r['ไฟล์ PDF (Drive ID)']||''),fileName:String(r['ชื่อไฟล์']||''),note:String(r['หมายเหตุ']||''),ackExpiry:normDate_(r['รับทราบวันหมดอายุ']),ackBy:String(r['รับทราบโดย']||''),ackAt:String(r['รับทราบเมื่อ']||''),updatedBy:String(r['อัปเดตโดย']||''),updatedAt:String(r['อัปเดตเมื่อ']||'')};});
}
function readDocHistory_(){
  var sh=ss_().getSheetByName(DOC_HISTORY_SHEET_NAME);if(!sh)return [];
  return rowsToObjects_(sh).map(function(r){return {at:String(r['เวลา']||''),vehicle:String(r['ชื่อรถ']||''),type:String(r['ประเภทเอกสาร']||''),docNo:String(r['เลขที่เอกสาร (เดิม)']||''),expiry:normDate_(r['วันหมดอายุ (เดิม)']),fileId:String(r['ไฟล์ PDF เดิม (Drive ID)']||''),fileName:String(r['ชื่อไฟล์เดิม']||''),note:String(r['หมายเหตุเดิม']||''),by:String(r['ดำเนินการโดย']||''),reason:String(r['เหตุผล']||'')};});
}
function getDocVehicles_(){
  var plateCols=['ป้ายทะเบียน','ทะเบียน','เลขทะเบียน'];
  return rowsToObjects_(sheet_(SHEETS.VEHICLES)).map(function(v){
    var plate='';for(var i=0;i<plateCols.length&&!plate;i++)plate=String(v[plateCols[i]]||'').trim();
    return {name:String(v['ชื่อรถ']||'').trim(),plate:plate,usagePermission:vehiclePermission_(v)};
  }).filter(function(v){return v.name;});
}
function docToClient_(d){return {id:d.id,vehicle:d.vehicle,type:d.type,docNo:d.docNo,expiry:d.expiry,hasFile:!!d.fileId,fileId:d.fileId,fileName:d.fileName,note:d.note,ackExpiry:d.ackExpiry,ackBy:d.ackBy,ackAt:d.ackAt,updatedBy:d.updatedBy,updatedAt:d.updatedAt,daysLeft:daysUntil_(d.expiry)};}
// แจ้งเตือน: เหลือ <= DOC_ALERT_DAYS_ วัน หรือหมดอายุแล้ว และยังไม่กด "รับทราบ" (รับทราบผูกกับวันหมดอายุนั้น ๆ ต่ออายุใหม่แล้วแจ้งเตือนรอบใหม่)
function computeDocAlerts_(docs){
  var out=[];
  docs.forEach(function(d){
    if(!d.expiry)return;var left=daysUntil_(d.expiry);if(left==null)return;
    if(left<=DOC_ALERT_DAYS_&&d.ackExpiry!==d.expiry)out.push({vehicle:d.vehicle,type:d.type,docNo:d.docNo,expiry:d.expiry,daysLeft:left});
  });
  out.sort(function(a,b){return a.daysLeft-b.daysLeft;});
  return out;
}
// อ่านอย่างเดียว: ข้อมูลทั้งหมดของแท็บ "เอกสารรถ"
function getVehicleDocs(adminToken){
  requireAdminSession_(adminToken);
  var docs=readDocs_();
  return {windowDays:DOC_ALERT_DAYS_,today:todayKey_(),types:DOC_TYPES_,vehicles:getDocVehicles_(),docs:docs.map(docToClient_),history:readDocHistory_().reverse().slice(0,300),alerts:computeDocAlerts_(docs)};
}
// อ่านอย่างเดียว: เฉพาะรายการแจ้งเตือน (เบา ใช้กับ Dashboard / ปฏิทิน)
function getDocAlerts(adminToken){
  requireAdminSession_(adminToken);
  var maint=readMaint_();
  return {windowDays:DOC_ALERT_DAYS_,alerts:computeDocAlerts_(readDocs_()),maintenance:computeMaintAlerts_(maint),lowReadiness:computeLowReadiness_(maint)};
}
function docUploadPdf_(file,vehicle,type,expiry){
  var b64=String(file.base64||'').replace(/^data:[^,]*,/,'');
  if(!b64)throw new Error('ไม่พบข้อมูลไฟล์');
  var bytes=Utilities.base64Decode(b64);
  if(bytes.length>DOC_MAX_BYTES_)throw new Error('ไฟล์ใหญ่เกิน '+Math.round(DOC_MAX_BYTES_/1048576)+' MB กรุณาลดขนาดไฟล์ PDF');
  if(!(bytes.length>4&&bytes[0]===37&&bytes[1]===80&&bytes[2]===68&&bytes[3]===70))throw new Error('ไฟล์ต้องเป็น PDF เท่านั้น');
  var clean=function(x){return String(x||'').replace(/[\\\/:*?"<>|]/g,'').replace(/\s+/g,'_');};
  var name=clean(vehicle)+'_'+clean(type)+'_'+clean(expiry)+'_'+Utilities.formatDate(new Date(),'Asia/Bangkok','yyyyMMddHHmmss')+'.pdf';
  var it=DriveApp.getFoldersByName(DOC_FOLDER_NAME_),folder=it.hasNext()?it.next():DriveApp.createFolder(DOC_FOLDER_NAME_);
  var f=folder.createFile(Utilities.newBlob(bytes,'application/pdf',name));
  return {id:f.getId(),name:name};
}
// mode: 'renew' = ต่ออายุ (ย้ายข้อมูลเดิมลงประวัติ แล้วบันทึกข้อมูลใหม่) | อื่น ๆ = สร้างใหม่/แก้ไขข้อมูลเดิม
function saveVehicleDoc(payload,adminToken){
  var admin=requireAdminSession_(adminToken),p=payload||{};
  var vehicle=String(p.vehicle||'').trim(),type=String(p.type||'').trim(),expiry=String(p.expiry||'').trim(),mode=p.mode==='renew'?'renew':'save';
  var docNo=String(p.docNo||'').trim().slice(0,80),note=String(p.note||'').trim().slice(0,500);
  if(!getDocVehicles_().some(function(v){return v.name===vehicle;}))throw new Error('ไม่พบรถคันนี้ในชีต Vehicles');
  if(DOC_TYPES_.indexOf(type)<0)throw new Error('ประเภทเอกสารไม่ถูกต้อง');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(expiry)||isNaN(new Date(expiry+'T00:00:00').getTime()))throw new Error('กรุณาระบุวันหมดอายุให้ถูกต้อง');
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var docs=readDocs_(),existing=null;
    docs.forEach(function(d){if(d.vehicle===vehicle&&d.type===type)existing=d;});
    if(mode==='renew'){
      if(!existing)throw new Error('ยังไม่มีข้อมูลเดิมของเอกสารนี้ จึงต่ออายุไม่ได้ (ให้บันทึกเป็นข้อมูลใหม่)');
      if(expiry<=existing.expiry)throw new Error('วันหมดอายุใหม่ต้องมากกว่าวันหมดอายุเดิม ('+existing.expiry+')');
    }
    var up=null;if(p.file&&p.file.base64)up=docUploadPdf_(p.file,vehicle,type,expiry);
    var who=admin.account,now=nowText_(),hs=docHistorySheet_();
    var pushHistory=function(d,reason){var r=hs.getLastRow()+1;hs.getRange(r,5,1,1).setNumberFormat('@');hs.getRange(r,1,1,10).setValues([[now,d.vehicle,d.type,d.docNo,d.expiry,d.fileId,d.fileName,d.note,who,reason]]);};
    var sh=docSheet_(),action,newRec;
    if(!existing){
      action='DOC_CREATE';
      newRec={id:'DOC-'+Utilities.getUuid().substring(0,8).toUpperCase(),vehicle:vehicle,type:type,docNo:docNo,expiry:expiry,fileId:up?up.id:'',fileName:up?up.name:'',note:note,ackExpiry:'',ackBy:'',ackAt:''};
      var r1=sh.getLastRow()+1;sh.getRange(r1,5,1,1).setNumberFormat('@');sh.getRange(r1,9,1,1).setNumberFormat('@');
      sh.getRange(r1,1,1,13).setValues([[newRec.id,vehicle,type,docNo,expiry,newRec.fileId,newRec.fileName,note,'','','',who,now]]);
    }else{
      var fileChanged=!!up;
      if(mode==='renew'){action='DOC_RENEW';pushHistory(existing,'ต่ออายุ');}
      else{action='DOC_EDIT';if(fileChanged&&existing.fileId)pushHistory(existing,'เปลี่ยนไฟล์แนบ');}
      var keepFile=(mode!=='renew'&&!fileChanged);
      newRec={id:existing.id,vehicle:vehicle,type:type,docNo:docNo,expiry:expiry,
        fileId:keepFile?existing.fileId:(up?up.id:''),fileName:keepFile?existing.fileName:(up?up.name:''),note:note,
        ackExpiry:(expiry===existing.expiry&&mode!=='renew')?existing.ackExpiry:'',ackBy:(expiry===existing.expiry&&mode!=='renew')?existing.ackBy:'',ackAt:(expiry===existing.expiry&&mode!=='renew')?existing.ackAt:''};
      sh.getRange(existing.row,5,1,1).setNumberFormat('@');sh.getRange(existing.row,9,1,1).setNumberFormat('@');
      sh.getRange(existing.row,1,1,13).setValues([[newRec.id,vehicle,type,docNo,expiry,newRec.fileId,newRec.fileName,note,newRec.ackExpiry,newRec.ackBy,newRec.ackAt,who,now]]);
    }
    var detail={record:{id:newRec.id,vehicle:vehicle,type:type,docNo:docNo,expiry:expiry,oldExpiry:existing?existing.expiry:'',oldDocNo:existing?existing.docNo:'',note:note,hasFile:!!newRec.fileId}};
    try{appendAuditLog_(action,newRec.id,who,existing?existing.expiry:'',expiry,vehicle+' / '+type,detail);}catch(e){}
    return {ok:true,action:action,id:newRec.id};
  }finally{lock.releaseLock();}
}
// "รับทราบ ไม่ต้องแจ้งเตือนอีก" — ผูกกับวันหมดอายุปัจจุบัน
function acknowledgeVehicleDoc(vehicle,type,adminToken){
  var admin=requireAdminSession_(adminToken);
  vehicle=String(vehicle||'').trim();type=String(type||'').trim();
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var d=null;readDocs_().forEach(function(x){if(x.vehicle===vehicle&&x.type===type)d=x;});
    if(!d)throw new Error('ไม่พบข้อมูลเอกสารนี้');
    var sh=docSheet_();sh.getRange(d.row,9,1,1).setNumberFormat('@');sh.getRange(d.row,9,1,3).setValues([[d.expiry,admin.account,nowText_()]]);
    try{appendAuditLog_('DOC_ACK',d.id,admin.account,'','',vehicle+' / '+type,{record:{id:d.id,vehicle:vehicle,type:type,docNo:d.docNo,expiry:d.expiry}});}catch(e){}
    return {ok:true};
  }finally{lock.releaseLock();}
}
// ดึงไฟล์ PDF มาดู/ดาวน์โหลดใน Admin — อนุญาตเฉพาะไฟล์ที่ระบบบันทึกไว้เอง (กันการอ่านไฟล์อื่นใน Drive)
function getVehicleDocFile(fileId,adminToken){
  requireAdminSession_(adminToken);
  fileId=String(fileId||'').trim();if(!fileId)throw new Error('ไม่ได้ระบุไฟล์');
  var known=readDocs_().some(function(d){return d.fileId===fileId;})||readDocHistory_().some(function(h){return h.fileId===fileId;});
  if(!known)throw new Error('ไม่พบไฟล์นี้ในระบบ');
  var f=DriveApp.getFileById(fileId),blob=f.getBlob();
  return {name:f.getName(),mime:'application/pdf',base64:Utilities.base64Encode(blob.getBytes())};
}
// รันครั้งเดียวจาก Apps Script Editor ก่อน Deploy เพื่ออนุมัติสิทธิ์ Google Drive (ไม่สร้าง/แก้ไขไฟล์ใดๆ)
function authorizeVehicleDocs(){var it=DriveApp.getFoldersByName(DOC_FOLDER_NAME_);return 'อนุมัติสิทธิ์ Google Drive แล้ว โฟลเดอร์ "'+DOC_FOLDER_NAME_+'" '+(it.hasNext()?'มีอยู่แล้ว':'จะถูกสร้างตอนอัปโหลดไฟล์ PDF ไฟล์แรก');}
// ===== V2.0.0: ประวัติการซ่อมบำรุง + ประเมินความพร้อมใช้งานของรถ (0-100%) =====
// ชีต MaintenanceHistory สร้างให้อัตโนมัติ: 1 แถวต่อการซ่อมบำรุง 1 ครั้ง
var MAINT_SHEET_NAME='MaintenanceHistory';
var MAINT_HEADERS_=['รหัส','ชื่อรถ','วันที่รับการซ่อมบำรุง','อาการเสีย / การซ่อมแซม','ต้องการแจ้งเตือน','สถานะการแจ้งเตือน','ความพร้อม (%)','จัดการแจ้งเตือนโดย','จัดการแจ้งเตือนเมื่อ','บันทึกโดย','บันทึกเมื่อ','แก้ไขล่าสุดโดย','แก้ไขล่าสุดเมื่อ'];
var MAINT_ST_={ACTIVE:'รอเข้ารับการซ่อม',DONE:'ดำเนินการแล้ว',DISMISSED:'ไม่ต้องแจ้งเตือนอีก'};
// เกณฑ์ประเมินความพร้อม (ตามเอกสาร Scope): 100 / 90 / 70 / 50 / ต่ำกว่า 50
var MAINT_TIERS_=[
  {min:100,level:100,label:'รับการบำรุงรักษาอยู่ตลอดไม่ขาด ไม่มีสัญญาณความผิดปกติ ไม่มีผู้ใช้คนใดแจ้งความผิดปกติ'},
  {min:90,level:90,label:'รับการบำรุงรักษาอยู่ตลอดไม่ขาด มีสัญญาณความผิดปกติหนึ่งรายการ ไม่รุนแรง ใช้ได้'},
  {min:70,level:70,label:'การบำรุงรักษาไม่ต่อเนื่อง มีสัญญาณความผิดปกติ 1 – 3 รายการ ไม่รุนแรง ใช้ได้'},
  {min:50,level:50,label:'การบำรุงรักษาไม่ต่อเนื่อง มีสัญญาณความผิดปกติ 3 - 5 รายการ ไม่รุนแรง ใช้ได้ในพื้นที่ใกล้เคียง'},
  {min:0,level:0,label:'ตรวจพบความผิดปกติ อันตราย ไม่ควรใช้งาน (น้อยกว่า 50%)'}
];
function maintTier_(score){for(var i=0;i<MAINT_TIERS_.length;i++)if(score>=MAINT_TIERS_[i].min)return MAINT_TIERS_[i];return MAINT_TIERS_[MAINT_TIERS_.length-1];}
function maintSheet_(){return getDocSheet_(MAINT_SHEET_NAME,MAINT_HEADERS_,[3,4]);}
function readMaint_(){
  var sh=ss_().getSheetByName(MAINT_SHEET_NAME);if(!sh)return [];
  return rowsToObjects_(sh).filter(function(r){return String(r['รหัส']||'');}).map(function(r){
    return {row:r._row,id:String(r['รหัส']||''),vehicle:String(r['ชื่อรถ']||''),date:normDate_(r['วันที่รับการซ่อมบำรุง']),desc:String(r['อาการเสีย / การซ่อมแซม']||''),notify:String(r['ต้องการแจ้งเตือน']||'')==='ต้องการ',alertStatus:String(r['สถานะการแจ้งเตือน']||''),score:Number(r['ความพร้อม (%)']),doneBy:String(r['จัดการแจ้งเตือนโดย']||''),doneAt:String(r['จัดการแจ้งเตือนเมื่อ']||''),createdBy:String(r['บันทึกโดย']||''),createdAt:String(r['บันทึกเมื่อ']||''),updatedBy:String(r['แก้ไขล่าสุดโดย']||''),updatedAt:String(r['แก้ไขล่าสุดเมื่อ']||'')};
  });
}
function maintLatestPerVehicle_(recs){
  var best={};
  recs.forEach(function(r){
    if(!(r.score>=0&&r.score<=100))return;
    var b=best[r.vehicle],k=r.date+'|'+r.createdAt;
    if(!b||k>=b.key)best[r.vehicle]={key:k,rec:r}; // เท่ากัน = แถวหลัง (บันทึกทีหลัง) ชนะ
  });
  var out={};Object.keys(best).forEach(function(v){var r=best[v].rec;out[v]={id:r.id,score:r.score,date:r.date,level:maintTier_(r.score).level};});
  return out;
}
function computeMaintAlerts_(recs){
  return recs.filter(function(r){return r.alertStatus===MAINT_ST_.ACTIVE;}).map(function(r){
    return {id:r.id,vehicle:r.vehicle,date:r.date,summary:r.desc.length>160?r.desc.slice(0,160)+'…':r.desc,daysLeft:daysUntil_(r.date),score:r.score};
  }).sort(function(a,b){return String(a.date).localeCompare(String(b.date));});
}
function computeLowReadiness_(recs){
  var latest=maintLatestPerVehicle_(recs),out=[];
  Object.keys(latest).forEach(function(v){if(latest[v].score<50)out.push({vehicle:v,score:latest[v].score,date:latest[v].date,id:latest[v].id});});
  return out;
}
function maintToClient_(r){return {id:r.id,vehicle:r.vehicle,date:r.date,desc:r.desc,notify:r.notify,alertStatus:r.alertStatus,score:r.score,level:maintTier_(r.score).level,doneBy:r.doneBy,doneAt:r.doneAt,createdBy:r.createdBy,createdAt:r.createdAt,updatedBy:r.updatedBy,updatedAt:r.updatedAt};}
// อ่านอย่างเดียว: ข้อมูลทั้งหมดของแท็บ "ซ่อมบำรุง"
function getMaintenance(adminToken){
  requireAdminSession_(adminToken);
  var recs=readMaint_();
  recs.sort(function(a,b){var x=a.date+'|'+a.createdAt,y=b.date+'|'+b.createdAt;return x<y?1:x>y?-1:0;});
  return {vehicles:getDocVehicles_(),tiers:MAINT_TIERS_,readiness:maintLatestPerVehicle_(recs),records:recs.slice(0,500).map(maintToClient_)};
}
// บันทึกใหม่ (ไม่ส่ง id) หรือแก้ไขรายการเดิม (ส่ง id)
function saveMaintenance(payload,adminToken){
  var admin=requireAdminSession_(adminToken),p=payload||{};
  var vehicle=String(p.vehicle||'').trim(),date=String(p.date||'').trim(),desc=String(p.desc==null?'':p.desc).replace(/\r\n/g,'\n').trim().slice(0,3000);
  var notify=(p.notify===true||p.notify==='true'||p.notify==='ต้องการ'),score=Number(p.score),id=String(p.id||'').trim();
  if(!getDocVehicles_().some(function(v){return v.name===vehicle;}))throw new Error('ไม่พบรถคันนี้ในชีต Vehicles');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||isNaN(new Date(date+'T00:00:00').getTime()))throw new Error('กรุณาเลือกวันที่รับการซ่อมบำรุงให้ถูกต้อง');
  if(!desc)throw new Error('กรุณาระบุอาการเสีย หรือการซ่อมแซม');
  if(p.score===''||p.score==null||!(score>=0&&score<=100)||Math.floor(score)!==score)throw new Error('กรุณาประเมินความพร้อมใช้งานเป็นจำนวนเต็ม 0–100%');
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var recs=readMaint_(),existing=null;if(id)recs.forEach(function(r){if(r.id===id)existing=r;});
    if(id&&!existing)throw new Error('ไม่พบรายการซ่อมบำรุงที่จะแก้ไข');
    var who=admin.account,now=nowText_(),sh=maintSheet_(),action,rec;
    if(!existing){
      action='MAINT_CREATE';
      rec={id:'MT-'+Utilities.getUuid().substring(0,8).toUpperCase(),vehicle:vehicle,date:date,desc:desc,notify:notify,alertStatus:notify?MAINT_ST_.ACTIVE:'',score:score,doneBy:'',doneAt:'',createdBy:who,createdAt:now,updatedBy:'',updatedAt:''};
      var r1=sh.getLastRow()+1;sh.getRange(r1,3,1,2).setNumberFormat('@');
      sh.getRange(r1,1,1,13).setValues([[rec.id,vehicle,date,desc,notify?'ต้องการ':'ไม่ต้องการ',rec.alertStatus,score,'','',who,now,'','']]);
    }else{
      action='MAINT_EDIT';
      var st=existing.alertStatus;
      if(notify&&!st)st=MAINT_ST_.ACTIVE;else if(!notify&&st===MAINT_ST_.ACTIVE)st='';
      rec={id:existing.id,vehicle:vehicle,date:date,desc:desc,notify:notify,alertStatus:st,score:score,doneBy:existing.doneBy,doneAt:existing.doneAt,createdBy:existing.createdBy,createdAt:existing.createdAt,updatedBy:who,updatedAt:now};
      sh.getRange(existing.row,3,1,2).setNumberFormat('@');
      sh.getRange(existing.row,1,1,13).setValues([[rec.id,vehicle,date,desc,notify?'ต้องการ':'ไม่ต้องการ',st,score,rec.doneBy,rec.doneAt,rec.createdBy,rec.createdAt,who,now]]);
    }
    try{appendAuditLog_(action,rec.id,who,existing?String(existing.score):'',String(score),vehicle,{record:{id:rec.id,vehicle:vehicle,maintDate:date,note:desc,score:score,oldScore:existing?existing.score:'',notify:notify?'ต้องการแจ้งเตือน':'ไม่ต้องการแจ้งเตือน'}});}catch(e){}
    return {ok:true,action:action,id:rec.id};
  }finally{lock.releaseLock();}
}
// ปุ่มในแผงแจ้งเตือน Dashboard: action = 'DONE' (ดำเนินการแล้ว) | 'DISMISS' (ไม่ต้องแจ้งเตือนอีก)
function resolveMaintenanceAlert(id,action,adminToken){
  var admin=requireAdminSession_(adminToken);
  id=String(id||'').trim();action=action==='DONE'?'DONE':'DISMISS';
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var rec=null;readMaint_().forEach(function(r){if(r.id===id)rec=r;});
    if(!rec)throw new Error('ไม่พบรายการซ่อมบำรุง');
    if(rec.alertStatus!==MAINT_ST_.ACTIVE)throw new Error('รายการนี้ไม่ได้อยู่ในสถานะรอเข้ารับการซ่อม');
    var sh=maintSheet_(),st=action==='DONE'?MAINT_ST_.DONE:MAINT_ST_.DISMISSED;
    sh.getRange(rec.row,6,1,1).setValue(st);sh.getRange(rec.row,8,1,2).setValues([[admin.account,nowText_()]]);
    try{appendAuditLog_(action==='DONE'?'MAINT_DONE':'MAINT_DISMISS',rec.id,admin.account,MAINT_ST_.ACTIVE,st,rec.vehicle,{record:{id:rec.id,vehicle:rec.vehicle,maintDate:rec.date,note:rec.desc,score:rec.score}});}catch(e){}
    return {ok:true,status:st};
  }finally{lock.releaseLock();}
}
var VEHICLE_PERMISSION_COL_='สิทธิ์การใช้งาน';
function vehiclePermission_(v){var p=String(v&&v[VEHICLE_PERMISSION_COL_]||'').trim().toUpperCase();return p==='RESTRICTED'?'RESTRICTED':'ALLOWED';}
function getVehicles(adminToken){requireAdminSession_(adminToken);return rowsToObjects_(sheet_(SHEETS.VEHICLES)).map(function(v){v.usagePermission=vehiclePermission_(v);return v;});}
function addVehicle(payload,adminToken){
  var admin=requireAdminSession_(adminToken),p=payload||{},name=String(p.name||'').trim().slice(0,120),plate=String(p.plate||'').trim().slice(0,40);
  var capacity=String(p.capacity==null?'':p.capacity).trim(),permission=String(p.usagePermission||'').trim().toUpperCase();
  if(!name)throw new Error('กรุณาระบุชื่อรถยนต์');if(['ALLOWED','RESTRICTED'].indexOf(permission)<0)throw new Error('กรุณาเลือกสิทธิ์การใช้งานรถ');
  if(capacity!==''&&(!/^\d+$/.test(capacity)||Number(capacity)<=0))throw new Error('จำนวนที่นั่งต้องเป็นตัวเลขมากกว่า 0');
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var sh=sheet_(SHEETS.VEHICLES),headers=sh.getRange(1,1,1,Math.max(sh.getLastColumn(),1)).getValues()[0].map(function(x){return String(x||'').trim();});
    if(headers.indexOf('ชื่อรถ')<0)throw new Error('ไม่พบคอลัมน์ "ชื่อรถ" ในชีต Vehicles');
    if(rowsToObjects_(sh).some(function(v){return String(v['ชื่อรถ']||'').trim().toLowerCase()===name.toLowerCase();}))throw new Error('มีชื่อรถนี้ในระบบแล้ว');
    function ensureHeader(h){var i=headers.indexOf(h);if(i>=0)return i;var col=headers.length+1;if(sh.getMaxColumns()<col)sh.insertColumnAfter(sh.getMaxColumns());sh.getRange(1,col).setValue(h);headers.push(h);return col-1;}
    var permissionIdx=ensureHeader(VEHICLE_PERMISSION_COL_),plateHeader=['ป้ายทะเบียน','ทะเบียน','เลขทะเบียน'].filter(function(h){return headers.indexOf(h)>=0;})[0]||'ป้ายทะเบียน';
    var plateIdx=ensureHeader(plateHeader),capacityIdx=headers.indexOf('ความจุ');if(capacity!==''&&capacityIdx<0)capacityIdx=ensureHeader('ความจุ');
    var row=new Array(headers.length).fill('');row[headers.indexOf('ชื่อรถ')]=name;row[plateIdx]=plate;row[permissionIdx]=permission;if(capacityIdx>=0&&capacity!=='')row[capacityIdx]=Number(capacity);
    sh.appendRow(row);try{appendAuditLog_('VEHICLE_CREATE','',admin.account,'','',name,{type:'VEHICLE_CREATE',vehicle:name,plate:plate,capacity:capacity,usagePermission:permission});}catch(e){}
    return {ok:true,name:name,usagePermission:permission};
  }finally{lock.releaseLock();}
}
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
// V1.2.9 (9 พ.ย. 69): ช่วงเวลาปฏิบัติหน้าที่ของคนขับ — ถ้า Admin ระบุไว้ใช้ช่วงนั้น ถ้าไม่ระบุ (ข้อมูลเก่า) ใช้ช่วงเวลาเดินทางของคำขอ
function dutyValue_(v){
  if(v===null||v===undefined||v==='')return '';
  if(v instanceof Date){if(isNaN(v.getTime()))return '';return Utilities.formatDate(v,Session.getScriptTimeZone(),"yyyy-MM-dd'T'HH:mm");}
  var m=String(v).trim().match(/^(\d{4}-\d{2}-\d{2})[T\s]+(\d{1,2}):(\d{2})/);
  if(!m)return '';
  return m[1]+'T'+String(parseInt(m[2],10)).padStart(2,'0')+':'+m[3];
}
function dutyRange_(o){
  var f=dutyValue_(o[DRIVER_FROM_COL_]),t=dutyValue_(o[DRIVER_TO_COL_]);
  if(f&&t&&f<t)return {start:f,end:t,d1:f.slice(0,10),d2:t.slice(0,10),t1:f.slice(11,16),t2:t.slice(11,16),explicit:true};
  var k=driverRangeKey_(o);k.explicit=false;return k;
}
function findDriverConflict_(rows,target,driver,win){
  var active=[STATUS.APPROVED,STATUS.ASSIGNED,STATUS.IN_USE],me=win||dutyRange_(target);
  for(var i=0;i<rows.length;i++){
    var o=rows[i];if(String(o.id)===String(target.id))continue;
    if(String(o[DRIVER_COL_]||'').trim()!==driver)continue;
    if(active.indexOf(String(o['สถานะ']||''))<0)continue;
    var k=dutyRange_(o);
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
function updateRequestStatus(id,status,vehiclesCsv,recordedBy,note,adminToken,driver,driverFrom,driverTo){
  var actingAdmin=requireAdminSession_(adminToken); recordedBy=actingAdmin.account;
  if(Object.keys(STATUS).map(function(k){return STATUS[k];}).indexOf(String(status))<0) throw new Error('สถานะที่ส่งมาไม่ถูกต้อง');
  if(String(status)===STATUS.ASSIGNED && !String(vehiclesCsv||'').trim()) throw new Error('ต้องเลือกอย่างน้อย 1 คันก่อนเปลี่ยนสถานะเป็นจัดรถแล้ว');
  var lock=LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var sh=sheet_(SHEETS.REQUESTS);ensureRequestColumns_(sh);var headers=sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0],rows=rowsToObjects_(sh),target=rows.find(function(r){return String(r.id)===String(id);});
    if(!target)throw new Error('ไม่พบคำขอรหัส: '+id);
    function col(n){var i=headers.indexOf(n);if(i<0)throw new Error('ไม่พบคอลัมน์ '+n+' ในชีต Requests');return i+1;}
    var selectedVehicleNames=String(vehiclesCsv||'').split(',').map(function(x){return x.trim();}).filter(Boolean);
    if(selectedVehicleNames.length){var fleet=rowsToObjects_(sheet_(SHEETS.VEHICLES));selectedVehicleNames.forEach(function(n){var found=null;fleet.forEach(function(v){if(String(v['ชื่อรถ']||'').trim()===n)found=v;});if(!found)throw new Error('ไม่พบรถ "'+n+'" ในทะเบียนรถ');if(vehiclePermission_(found)==='RESTRICTED')throw new Error('รถ '+n+' เป็นรถผู้บริหาร ไม่สามารถนำมาจัดสรรให้คำขอใช้รถได้');});}
    var driverToSet=null,dutyFrom='',dutyTo='';
    if(driver!==undefined&&driver!==null){
      driver=String(driver).trim();
      if(driver){
        if(getDriverNames_().indexOf(driver)<0)throw new Error('ไม่พบพนักงานขับรถ "'+driver+'" ในชีต Drivers');
        dutyFrom=dutyValue_(driverFrom);dutyTo=dutyValue_(driverTo);
        if(!dutyFrom||!dutyTo)throw new Error('กรุณาระบุวันและเวลาที่พนักงานขับรถปฏิบัติหน้าที่ (ตั้งแต่ - ถึง)');
        if(dutyFrom>=dutyTo)throw new Error('เวลาสิ้นสุดการปฏิบัติหน้าที่ของคนขับต้องอยู่หลังเวลาเริ่มต้น');
        if([STATUS.APPROVED,STATUS.ASSIGNED,STATUS.IN_USE].indexOf(String(status))>-1){
          var hit=findDriverConflict_(rows,target,driver,{start:dutyFrom,end:dutyTo});
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
      [[DRIVER_FROM_COL_,dutyFrom],[DRIVER_TO_COL_,dutyTo]].forEach(function(p){
        var ci=headers.indexOf(p[0]);if(ci<0)return;
        var cell=sh.getRange(target._row,ci+1);cell.setNumberFormat('@');
        cell.setValue(driverToSet&&p[1]?p[1].replace('T',' '):'');
      });
    }
    if(recordedBy)sh.getRange(target._row,col('ผู้บันทึก')).setValue(recordedBy);
    if(note!==undefined&&note!==null)sh.getRange(target._row,col('หมายเหตุ')).setValue(note);
    return {ok:true};
  } finally {lock.releaseLock();}
}
function forecastVehicles(students,teachers,others,adminToken){requireAdminSession_(adminToken);var vehicles=getVehicles(adminToken).filter(function(v){return v.usagePermission!=='RESTRICTED';}).sort(function(a,b){return Number(b['ความจุ'])-Number(a['ความจุ']);}),groups=[{label:'นักเรียน',count:Number(students)||0},{label:'ครู',count:Number(teachers)||0},{label:'อื่นๆ',count:Number(others)||0}].filter(function(g){return g.count>0;}),plan=[],cautions=[],i=0,current=vehicles[0],remain=current?Number(current['ความจุ']):0,open=null;groups.forEach(function(g){var left=g.count;while(left>0&&current){var take=Math.min(left,remain);if(!open||open.vehicle!==current['ชื่อรถ']){open={vehicle:current['ชื่อรถ'],count:0,detail:[]};plan.push(open);}open.count+=take;open.detail.push(g.label+' '+take+' คน');left-=take;remain-=take;if(remain<=0){current=vehicles[++i];remain=current?Number(current['ความจุ']):0;open=null;}}if(left>0)cautions.push('รถในกองรถไม่พอสำหรับ'+g.label+'อีก '+left+' คน — ต้องพิจารณาวิ่งเพิ่มเที่ยว หรือหาทางเลือกอื่น');});plan.forEach(function(p){var v=vehicles.find(function(x){return x['ชื่อรถ']===p.vehicle;});if(v&&Number(v['ความจุ'])>=13&&p.count<=Number(v['ความจุ'])*.25)cautions.push(p.vehicle+' บรรทุกแค่ '+p.count+' คน (จุได้ '+v['ความจุ']+') — ลองย้ายไปรวมกับคันอื่นที่ยังมีที่ว่างแทนได้');});if(plan.filter(function(p){return p.vehicle.indexOf('หกล้อ')>-1;}).length>=2)cautions.push('ถ้าระยะทางใกล้พอให้รถหกล้อวิ่ง 2 เที่ยวทันเวลา อาจลดจำนวนรถที่ใช้ได้ — ควรโทรถามครูผู้ขอเรื่องระยะเวลาก่อนตัดสินใจ');return {plan:plan,cautions:cautions};}

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
function updateRequestStatusWithAudit(id,status,vehicles,recordedBy,note,adminToken,driver,driverFrom,driverTo){
  var actingAdmin=requireAdminSession_(adminToken); recordedBy=actingAdmin.account;
  var before=findRequestRowById_(id); if(!before)throw new Error('ไม่พบรายการคำขอ: '+id);
  var result=updateRequestStatus(id,status,vehicles,recordedBy,note,adminToken,driver,driverFrom,driverTo),after=findRequestRowById_(id);
  appendAuditLog_('UPDATE',id,recordedBy||'',before.object['สถานะ']||'',status||'',vehicles||'',{type:'UPDATE',before:before.object,after:after?after.object:{status:status,vehicles:vehicles},note:note||'',previousVehicles:before.object['รถที่จัด']||'',previousDriver:before.object[DRIVER_COL_]||'',driver:after?(after.object[DRIVER_COL_]||''):'',driverFrom:after?dutyValue_(after.object[DRIVER_FROM_COL_]):'',driverTo:after?dutyValue_(after.object[DRIVER_TO_COL_]):''}); return result;
}
function deleteRequest(id,adminToken){
  var actingAdmin=requireAdminSession_(adminToken); var admin=actingAdmin.account;
  var lock=LockService.getScriptLock();lock.waitLock(10000);
  try{var found=findRequestRowById_(id);if(!found)throw new Error('ไม่พบรายการคำขอ: '+id);appendAuditLog_('DELETE',id,admin||'',found.object['สถานะ']||'','ลบรายการ',found.object['รถที่จัด']||'',{type:'DELETE',deletedRequest:found.object});found.sheet.deleteRow(found.row);return true;}
  finally{lock.releaseLock();}
}
function deleteRequests(ids,adminToken){
  var actingAdmin=requireAdminSession_(adminToken),admin=actingAdmin.account;
  if(!Array.isArray(ids)||!ids.length)throw new Error('กรุณาเลือกรายการที่ต้องการลบ');
  if(ids.length>200)throw new Error('ลบได้ไม่เกิน 200 รายการต่อครั้ง');
  var unique=[],seen={};
  ids.forEach(function(value){var id=String(value==null?'':value).trim();if(id&&!seen[id]){seen[id]=true;unique.push(id);}});
  if(!unique.length)throw new Error('ไม่พบรหัสรายการที่ถูกต้อง');
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var sh=sheet_(SHEETS.REQUESTS),values=sh.getDataRange().getValues();
    if(!values.length)throw new Error('ไม่พบข้อมูลคำขอ');
    var headers=values[0],idCol=headers.indexOf('id');
    if(idCol<0)throw new Error('ไม่พบคอลัมน์ id ในชีต Requests');
    var rowById={};
    for(var i=1;i<values.length;i++){var key=String(values[i][idCol]||'');if(key&&seen[key]){var obj={};headers.forEach(function(h,j){obj[h]=values[i][j];});rowById[key]={row:i+1,object:obj};}}
    var missing=unique.filter(function(id){return !rowById[id];});
    if(missing.length)throw new Error('ไม่พบรายการต่อไปนี้ (ไม่มีการลบรายการใด): '+missing.join(', '));
    var ordered=unique.map(function(id){return {id:id,row:rowById[id].row,object:rowById[id].object};}).sort(function(a,b){return b.row-a.row;});
    var deleted=[];
    ordered.forEach(function(item){
      appendAuditLog_('DELETE',item.id,admin||'',item.object['สถานะ']||'','ลบรายการ',item.object['รถที่จัด']||'',{type:'BULK_DELETE',deletedRequest:item.object,batchSize:unique.length});
      sh.deleteRow(item.row);
      deleted.push(item.id);
    });
    return {ok:true,deleted:deleted.length,deletedIds:deleted,failed:[]};
  }finally{lock.releaseLock();}
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

// ===== V1.2.9 (9 พ.ย. 69): Admin แก้ไขรายละเอียดคำขอ + ปุ่มดำเนินการแล้วเสร็จ =====
// แก้ไขข้อมูลที่ผู้ขอกรอกมา (ไม่แตะสถานะ / รถที่จัด / ผู้บันทึก) และบันทึกก่อน-หลังแก้ไว้ใน AuditLog (action = EDIT_DETAILS)
function updateRequestDetails(id,data,adminToken){
  var actingAdmin=requireAdminSession_(adminToken),admin=actingAdmin.account;
  data=data||{};
  var txt=function(v,n){return String(v==null?'':v).trim().slice(0,n);};
  var f={staffId:txt(data.staffId,30),name:txt(data.name,120),position:txt(data.position,120),department:txt(data.department,120),destination:txt(data.destination,250),purpose:txt(data.purpose,500),dateGo:txt(data.dateGo,10),timeGo:txt(data.timeGo,5),dateBack:txt(data.dateBack,10),timeBack:txt(data.timeBack,5),companionNames:txt(data.companionNames,2000),note:txt(data.note,1000),requestedDriver:txt(data.requestedDriver,120),requesterPhone:cleanPhone_(data.requesterPhone)};
  var needDriver=(data.needDriver===true||data.needDriver==='1'||data.needDriver==='ต้องการ');
  if(needDriver)f.requestedDriver='';
  var num=function(v){return Math.max(0,Math.floor(Number(v))||0);};
  var nums={companionCount:num(data.companionCount),students:num(data.students),teachers:num(data.teachers),others:num(data.others)};
  if(!f.name||!f.destination||!f.purpose||!f.dateGo||!f.timeGo)throw new Error('กรุณากรอกชื่อ ปลายทาง วัตถุประสงค์ วันที่ไป และเวลาไป');
  if(!needDriver&&!f.requestedDriver)throw new Error('กรณีไม่ต้องการคนขับจากโรงเรียน กรุณาระบุชื่อผู้ขับรถ');
  var phoneDigits=f.requesterPhone.replace(/\D/g,'');
  if(phoneDigits&&(phoneDigits.length<9||phoneDigits.length>15))throw new Error('เบอร์โทรศัพท์ไม่ถูกต้อง');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(f.dateGo)||!/^\d{2}:\d{2}$/.test(f.timeGo))throw new Error('รูปแบบวันที่หรือเวลาไม่ถูกต้อง');
  if(f.dateBack&&!/^\d{4}-\d{2}-\d{2}$/.test(f.dateBack))throw new Error('รูปแบบวันที่กลับไม่ถูกต้อง');
  if(f.timeBack&&!/^\d{2}:\d{2}$/.test(f.timeBack))throw new Error('รูปแบบเวลากลับไม่ถูกต้อง');
  if(f.dateBack&&f.dateBack<f.dateGo)throw new Error('วันที่กลับต้องไม่อยู่ก่อนวันที่เดินทางไป');
  var lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    var sh=sheet_(SHEETS.REQUESTS);ensureRequestColumns_(sh);
    var found=findRequestRowById_(id);if(!found)throw new Error('ไม่พบรายการคำขอ: '+id);
    var headers=found.headers;
    var map={'รหัสบุคลากร':f.staffId,'ชื่อ-นามสกุล':f.name,'ตำแหน่ง':f.position,'สังกัด':f.department,'ปลายทาง':f.destination,'วัตถุประสงค์':f.purpose,'วันที่ไป':f.dateGo,'เวลาไป':f.timeGo,'วันที่กลับ':f.dateBack,'เวลากลับ':f.timeBack,'ต้องการคนขับ':needDriver?'ต้องการ':'ไม่ต้องการ','จำนวนผู้ร่วมเดินทาง':nums.companionCount,'รายชื่อผู้ร่วมเดินทาง':f.companionNames,'จำนวนนักเรียน':nums.students,'จำนวนครู':nums.teachers,'จำนวนอื่นๆ':nums.others,'หมายเหตุ':f.note};
    map[REQ_DRIVER_NAME_COL_]=f.requestedDriver;map[REQ_PHONE_COL_]=f.requesterPhone;
    if(!needDriver){map[DRIVER_COL_]='';map[DRIVER_FROM_COL_]='';map[DRIVER_TO_COL_]='';} // เปลี่ยนเป็นไม่ต้องการคนขับจากโรงเรียน: ล้างคนขับที่จัดไว้เดิม
    Object.keys(map).forEach(function(h){
      var ci=headers.indexOf(h);if(ci<0)return;
      var cell=found.sheet.getRange(found.row,ci+1);
      if(h===REQ_PHONE_COL_||h===DRIVER_FROM_COL_||h===DRIVER_TO_COL_)cell.setNumberFormat('@');
      cell.setValue(map[h]);
    });
    var after=findRequestRowById_(id),warning='';
    var status=String(found.object['สถานะ']||''),drv=String(found.object[DRIVER_COL_]||'').trim();
    if(needDriver&&drv&&[STATUS.APPROVED,STATUS.ASSIGNED,STATUS.IN_USE].indexOf(status)>-1&&after){
      var hit=findDriverConflict_(rowsToObjects_(found.sheet),after.object,drv);
      if(hit)warning='แก้ไขรายละเอียดเรียบร้อยแล้ว แต่ พนักงานขับรถ '+drv+' ซ้อนเวลากับรายการของ '+String(hit.row['ชื่อ-นามสกุล']||'-')+' ('+thaiDateText_(hit.range.d1)+' เวลา '+hit.range.t1+' - '+hit.range.t2+' น.) กรุณาตรวจสอบช่วงเวลาปฏิบัติหน้าที่ของคนขับในหน้าจัดรถ';
    }
    appendAuditLog_('EDIT_DETAILS',id,admin,status,status,found.object['รถที่จัด']||'',{type:'EDIT_DETAILS',before:found.object,after:after?after.object:{}});
    return {ok:true,warning:warning};
  }finally{lock.releaseLock();}
}
// ปุ่ม "ดำเนินการแล้วเสร็จ": เปลี่ยนสถานะเป็นเสร็จสิ้น (รายการหายจากแท็บจัดรถ แต่ยังอยู่ในปฏิทิน/รายงาน) และบันทึกใน AuditLog (action = COMPLETE)
function completeRequest(id,adminToken){
  var actingAdmin=requireAdminSession_(adminToken),admin=actingAdmin.account;
  var lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    var found=findRequestRowById_(id);if(!found)throw new Error('ไม่พบรายการคำขอ: '+id);
    var oldStatus=String(found.object['สถานะ']||'');
    if(oldStatus===STATUS.CANCELLED||oldStatus===STATUS.REJECTED)throw new Error('คำขอที่ยกเลิกหรือปฏิเสธไม่ต้องกดดำเนินการแล้วเสร็จ หากไม่ต้องการแสดงให้ใช้ปุ่มลบคำขอ');
    var ci=found.headers.indexOf('สถานะ');if(ci<0)throw new Error('ไม่พบคอลัมน์ สถานะ ในชีต Requests');
    found.sheet.getRange(found.row,ci+1).setValue(STATUS.DONE);
    var after=findRequestRowById_(id);
    appendAuditLog_('COMPLETE',id,admin,oldStatus,STATUS.DONE,found.object['รถที่จัด']||'',{type:'COMPLETE',before:found.object,after:after?after.object:{}});
    return {ok:true};
  }finally{lock.releaseLock();}
}
function completeRequests(ids,adminToken){
  var actingAdmin=requireAdminSession_(adminToken),admin=actingAdmin.account;
  if(!Array.isArray(ids)||!ids.length)throw new Error('กรุณาเลือกรายการที่ต้องการดำเนินการ');
  if(ids.length>200)throw new Error('ดำเนินการได้ไม่เกิน 200 รายการต่อครั้ง');
  var unique=[],seen={};
  ids.forEach(function(value){var id=String(value==null?'':value).trim();if(id&&!seen[id]){seen[id]=true;unique.push(id);}});
  if(!unique.length)throw new Error('ไม่พบรหัสรายการที่ถูกต้อง');
  var lock=LockService.getScriptLock();lock.waitLock(15000);
  try{
    var sh=sheet_(SHEETS.REQUESTS),values=sh.getDataRange().getValues();
    if(!values.length)throw new Error('ไม่พบข้อมูลคำขอ');
    var headers=values[0],idCol=headers.indexOf('id'),statusCol=headers.indexOf('สถานะ');
    if(idCol<0)throw new Error('ไม่พบคอลัมน์ id ในชีต Requests');
    if(statusCol<0)throw new Error('ไม่พบคอลัมน์ สถานะ ในชีต Requests');
    var rowById={};
    for(var i=1;i<values.length;i++){
      var key=String(values[i][idCol]||'');
      if(key&&seen[key]){var obj={};headers.forEach(function(h,j){obj[h]=values[i][j];});rowById[key]={row:i+1,object:obj};}
    }
    var missing=unique.filter(function(id){return !rowById[id];});
    if(missing.length)throw new Error('ไม่พบรายการต่อไปนี้ (ไม่มีการเปลี่ยนสถานะรายการใด): '+missing.join(', '));
    var completed=[],skipped=[];
    unique.forEach(function(id){
      var item=rowById[id],oldStatus=String(item.object['สถานะ']||'');
      if(oldStatus===STATUS.CANCELLED||oldStatus===STATUS.REJECTED){skipped.push({id:id,reason:oldStatus});return;}
      sh.getRange(item.row,statusCol+1).setValue(STATUS.DONE);
      appendAuditLog_('COMPLETE',id,admin,oldStatus,STATUS.DONE,item.object['รถที่จัด']||'',{type:'BULK_COMPLETE',before:item.object,after:Object.assign({},item.object,{'สถานะ':STATUS.DONE}),batchSize:unique.length});
      completed.push(id);
    });
    return {ok:true,completed:completed.length,completedIds:completed,skipped:skipped};
  }finally{lock.releaseLock();}
}


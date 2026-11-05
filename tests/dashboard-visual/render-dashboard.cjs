const { chromium } = require('playwright');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

(async () => {
  const html = fs.readFileSync(path.join(process.cwd(), 'Admin.html'), 'utf8');
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(html); });
  await new Promise(resolve => server.listen(4173, '127.0.0.1', resolve));
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1672, height: 941 }, deviceScaleFactor: 1 });
  page.on('pageerror', error => console.error('PAGE_ERROR:', error.message));
  await page.goto('http://127.0.0.1:4173', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForTimeout(1200);
  const result = await page.evaluate(() => {
    try {
      if (typeof requests !== 'undefined') requests = [];
      if (typeof vehicles !== 'undefined') vehicles = [];
      if (typeof drivers !== 'undefined') drivers = [];
      if (typeof maintAlerts !== 'undefined') maintAlerts = [];
      if (typeof lowReady !== 'undefined') lowReady = [];
      if (typeof dashboardSetTheme === 'function') dashboardSetTheme('dark');
      const overlay = document.getElementById('authOverlay');
      if (overlay) overlay.style.display = 'none';
      document.querySelectorAll('.view').forEach(el => el.style.display = 'none');
      const dash = document.getElementById('v-dashboard');
      if (dash) { dash.style.display = 'block'; dash.classList.add('active'); }
      if (typeof renderDashboard === 'function') renderDashboard();
      if (typeof dashboardRenderCalendar === 'function') dashboardRenderCalendar();
      // Deterministic visual fixtures: browser-only DOM content, no production writes.
      const set = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
      set('dashboardFleetTotal','28'); set('dashboardFleetReady','24'); set('dashboardFleetMaint','2'); set('dashboardFleetUnavailable','2');
      set('dashboardFleetReadyPct','85.7% พร้อมใช้งาน'); set('dashboardTodayCount','4'); set('dashboardPendingCount','6');
      const table = document.getElementById('dashboardTodayTable');
      if (table) table.innerHTML = '<tr><td>08:00–12:00</td><td>ทะเบียน 1234</td><td>คุณสมชาย ใจดี</td><td>กทม.</td><td>เสร็จสิ้น</td></tr><tr><td>09:00–16:00</td><td>ทะเบียน 5678</td><td>คุณณัฐวุฒิ สุขใจ</td><td>อยุธยา</td><td>กำลังใช้งาน</td></tr><tr><td>10:00–15:00</td><td>ทะเบียน 9012</td><td>คุณวิภาวี มีสุข</td><td>ปทุมธานี</td><td>กำลังใช้งาน</td></tr><tr><td>13:00–17:00</td><td>ทะเบียน 3456</td><td>คุณอรรถพล ดีมาก</td><td>นครปฐม</td><td>รอจัดรถ</td></tr>';
      const pending = document.getElementById('dashboardPending');
      if (pending) pending.innerHTML = '<div class="dashboard-request"><b>คำขอใช้รถใหม่</b><div>รออนุมัติ 2 รายการ</div></div><div class="dashboard-request"><b>ยังไม่ได้จัดรถ / ระบุคนขับ</b><div>1 รายการ</div></div>';
      const maint = document.getElementById('dashboardMaintAlerts');
      if (maint) maint.innerHTML = '<div class="dashboard-request">รถเข้าเช็กระยะ (7 วัน) · 1 รายการ</div>';
      const docs = document.getElementById('dashboardDocumentAlerts');
      if (docs) docs.innerHTML = '<div class="dashboard-doc">เอกสารใกล้หมดอายุ · 2 รายการ</div>';
      const chart = document.getElementById('dashboardMonthlyChart');
      if (chart) chart.innerHTML = '<div class="month-bar"><strong>22</strong><div class="month-bar-track"><div class="month-bar-fill" style="height:74%"></div></div><small>ม.ค.</small></div><div class="month-bar"><strong>25</strong><div class="month-bar-track"><div class="month-bar-fill" style="height:84%"></div></div><small>ก.พ.</small></div><div class="month-bar"><strong>24</strong><div class="month-bar-track"><div class="month-bar-fill" style="height:80%"></div></div><small>มี.ค.</small></div><div class="month-bar"><strong>26</strong><div class="month-bar-track"><div class="month-bar-fill" style="height:88%"></div></div><small>เม.ย.</small></div><div class="month-bar"><strong>23</strong><div class="month-bar-track"><div class="month-bar-fill" style="height:77%"></div></div><small>พ.ค.</small></div><div class="month-bar"><strong>24</strong><div class="month-bar-track"><div class="month-bar-fill" style="height:80%"></div></div><small>มิ.ย.</small></div>';
      set('dashboardHealthPct','85.7%');
      const donut = document.getElementById('dashboardHealthDonut');
      if (donut) donut.style.background = 'conic-gradient(#10bd78 0 85.7%,#ffb000 85.7% 93%,#ef344e 93% 100%)';
      const legend = document.getElementById('dashboardHealthLegend');
      if (legend) legend.innerHTML = '<span>🟢 พร้อมใช้งาน　24 คัน</span><span>🟡 ซ่อมบำรุง　2 คัน</span><span>🔴 ไม่พร้อมใช้　2 คัน</span>';
      const status = document.getElementById('dashboardDocumentStatus');
      if (status) status.innerHTML = '<div class="document-row"><span>พ.ร.บ.</span><div class="document-track"><div class="document-fill" style="width:86%"></div></div><strong>24/28 คัน</strong></div><div class="document-row"><span>ประกัน</span><div class="document-track"><div class="document-fill" style="width:89%"></div></div><strong>25/28 คัน</strong></div><div class="document-row"><span>ภาษี</span><div class="document-track"><div class="document-fill" style="width:93%"></div></div><strong>26/28 คัน</strong></div><div class="document-row"><span>ทะเบียน</span><div class="document-track"><div class="document-fill" style="width:100%"></div></div><strong>28/28 คัน</strong></div>';
      set('dashboardRecommendation','เอกสาร พ.ร.บ. ของรถทะเบียน 1234 จะหมดอายุในอีก 45 วัน กรุณาต่ออายุเพื่อความต่อเนื่องในการใช้งาน');
      return { ok: !!dash, title: document.querySelector('.dashboard-toolbar-title')?.textContent || '', bodyWidth: document.body.scrollWidth, bodyHeight: document.body.scrollHeight };
    } catch (e) { return { ok: false, error: String(e.stack || e) }; }
  });
  console.log('DASHBOARD_RESULT', JSON.stringify(result));
  await page.screenshot({ path: 'dashboard-dark.png', fullPage: false });
  await page.evaluate(() => { if (typeof dashboardSetTheme === 'function') dashboardSetTheme('light'); });
  await page.waitForTimeout(250);
  await page.screenshot({ path: 'dashboard-light.png', fullPage: false });
  await browser.close();
  await new Promise(resolve => server.close(resolve));
  if (!result.ok) process.exitCode = 1;
})();

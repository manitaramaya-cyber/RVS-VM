const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const html = fs.readFileSync(path.join(process.cwd(), 'Admin.html'), 'utf8');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1100 }, deviceScaleFactor: 1 });
  page.on('pageerror', error => console.error('PAGE_ERROR:', error.message));
  await page.setContent(html, { waitUntil: 'networkidle', timeout: 60000 }).catch(async () => {
    await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: 60000 });
  });
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
      return { ok: !!dash, title: document.querySelector('.dashboard-toolbar-title')?.textContent || '', bodyWidth: document.body.scrollWidth, bodyHeight: document.body.scrollHeight };
    } catch (e) { return { ok: false, error: String(e.stack || e) }; }
  });
  console.log('DASHBOARD_RESULT', JSON.stringify(result));
  await page.screenshot({ path: 'dashboard-dark.png', fullPage: true });
  await page.evaluate(() => { if (typeof dashboardSetTheme === 'function') dashboardSetTheme('light'); });
  await page.waitForTimeout(250);
  await page.screenshot({ path: 'dashboard-light.png', fullPage: true });
  await browser.close();
  if (!result.ok) process.exitCode = 1;
})();

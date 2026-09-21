import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';

const edge = process.env.WAYTRACE_BROWSER || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const supported = fs.existsSync(edge);
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'waytrace-ui-'));
process.env.WAYTRACE_DB_PATH = path.join(directory, 'test.db');
const { app } = await import('../server.js');
const db = await import('../backend/database.js');
let server, browser;
after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
  db.closeDb();
  fs.rmSync(directory, { recursive: true, force: true });
});

test('desktop and mobile dashboard workflows', { skip: !supported }, async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  browser = await chromium.launch({ executablePath: edge, headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.getByRole('button', { name: /End-to-End Account Compromise/ }).click();
  await page.locator('#incTitle').getByText(/Possible Account Compromise/).waitFor();
  assert.ok(Number(await page.locator('#incRisk').textContent()) >= 85);
  await page.getByRole('button', { name: 'View All' }).click();
  await page.locator('#notificationsDialog').getByText(/Possible Account Compromise/).waitFor();
  await page.getByRole('button', { name: 'Close notifications' }).click();
  await page.getByRole('button', { name: 'Evidence Store' }).click();
  assert.ok((await page.locator('#evidenceContainer tr').count()) > 1);
  await page.getByRole('button', { name: /Password Spraying/ }).click();
  await page.locator('#incTitle').getByText(/Password Spraying/).waitFor();
  assert.match(await page.locator('#domainTag').textContent(), /Authentication/);
  const screenshots = process.env.WAYTRACE_SCREENSHOT_DIR;
  if (screenshots) { fs.mkdirSync(screenshots, { recursive: true }); await page.screenshot({ path: path.join(screenshots, 'desktop.png'), fullPage: true }); }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await page.locator('#incidentsList tr').first().waitFor();
  await page.waitForFunction(() => !document.querySelector('#connectionsList')?.textContent.includes('Loading local socket'));
  await page.locator('#incidentsList button').first().click();
  await page.locator('#incTitle').getByText(/Possible Account Compromise/).waitFor();
  const width = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
  if (screenshots) await page.screenshot({ path: path.join(screenshots, 'mobile.png'), fullPage: true });
  assert.ok(width.scroll <= width.client + 2, `horizontal overflow: ${JSON.stringify(width)}`);
  await page.goto(`http://127.0.0.1:${server.address().port}/docs/`);
  await page.locator('.swagger-ui .info .title').waitFor();
  assert.match(await page.locator('.swagger-ui .info .title').textContent(), /WayTrace API/);
  assert.deepEqual(errors, []);
});

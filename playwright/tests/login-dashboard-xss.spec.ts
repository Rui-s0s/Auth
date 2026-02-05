import { test, expect, Page, defineConfig } from '@playwright/test';

declare global {
  interface Window {
    xssFlag?: boolean;
  }
}


const users = [
  { id: 1, username: '<script>alert("Classic XSS")</script>', password: '...' },
  { id: 2, username: '<img src=x onerror=alert("EventXSS")>', password: '...' },
  { id: 3, username: '"><script>alert("AttributeBreak")</script>', password: '...' },
  { id: 4, username: 'javascript:alert("LinkXSS")', password: '...' },
  { id: 5, username: '<svg onload=alert("SVG_XSS")>', password: '...' },
  { id: 6, username: '<div style="width: expression(alert(\'IE_XSS\'));">', password: '...' }
];

async function watchForXSS(page: Page) {
  let triggered = false;
  page.on('dialog', async d => {
    triggered = true;
    await d.dismiss();
  });
  return () => triggered;
}

test.describe('Login → Dashboard security', () => {
  for (const user of users) {
    test(`Payload ${user.id} should render safely and logout works`, async ({ page }) => {
      const xssTriggered = await watchForXSS(page);
        console.log('Going to localhost3000')
      // ---- LOGIN ----
      await page.goto('http://localhost:3000/');

      await page.waitForSelector('#username', { state: 'visible' });
      await page.waitForSelector('#password', { state: 'visible' });

      console.log('trying to fill stuff')
      
      await page.getByPlaceholder('Username').fill(user.username);
      await page.getByPlaceholder('Password').fill(user.password);

      await page.click('#loginSession');

      // login.js does fetch → sets cookie but no redirect
      await page.waitForLoadState('networkidle');

      await page.goto('http://localhost:3000/dashboard');

      // Username must appear as TEXT, not HTML
      const welcome = page.locator('h1');
      await expect(welcome).toContainText(user.username);

        await expect(page.locator('img')).toHaveCount(0);
        await expect(page.locator('script')).toHaveCount(0);
        await expect(page.locator('svg')).toHaveCount(0);

      // ---- LOGOUT ----
      await page.click('#logoutBtn');


      // Should be logged out (redirect or login page visible)
    });
  }
});



// npx playwright test --headed --debug

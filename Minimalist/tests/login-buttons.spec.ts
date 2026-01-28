import { test, expect } from '@playwright/test';

test.describe('Login buttons', () => {

  test('Login with JWT works', async ({ page }) => {
    await page.goto('http://localhost:8888/login');

    // Fill form
    await page.fill('#username', 'alice');
    await page.fill('#password', 'password123');

    // Watch network request (adjust URL to your API)
    const responsePromise = page.waitForResponse(res =>
      res.url().includes('/login') && res.status() === 200
    );

    // Click JWT button
    await page.click('#loginJwt');

    const response = await responsePromise;
    expect(response.ok()).toBeTruthy();

    // Example: redirected to dashboard
    await expect(page).toHaveURL(/\/protected$/);


    // Wait until accessToken is defined in the browser
    await page.waitForFunction(() => (window as any).accessToken !== undefined);

    const token = await page.evaluate(() => (window as any).accessToken);
    expect(token).toBeTruthy();
  });


  test('Login with Session works', async ({ page }) => {
    await page.goto('http://localhost:8888/login');

    await page.fill('#username', 'alice');
    await page.fill('#password', 'password123');

    const responsePromise = page.waitForResponse(res =>
      res.url().includes('/login') && res.status() === 200
    );

    await page.click('#loginSession');
    await page.waitForURL(/\/protected$/);


    const cookies = await page.context().cookies();
    expect(cookies.some(c => c.name === 'connect.sid')).toBeTruthy();
  });

});
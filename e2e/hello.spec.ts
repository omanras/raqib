import { expect, test } from "@playwright/test";

test("the page renders the Qayd heading and the app version", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Qayd");
  await expect(page.getByTestId("version")).toHaveText(/^\d+\.\d+\.\d+/);
});

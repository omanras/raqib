// Files: export by copy and download equal to the bundled bytes; import
// refusing a wrong header or bytes that are not UTF-8, by file, several at
// once, or pasted.
import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { example, expectCounts, FILES } from "./helpers";

test("export copies text equal to the bundled file, and download offers it", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/");
  await page.getByTestId("load-sample").click();
  await page.getByRole("link", { name: "Files" }).click();
  for (const name of ["ledger.csv", "policies.yml"]) {
    await page.getByTestId(`copy-${name}`).click();
    await expect(page.getByTestId(`file-${name}`).getByRole("status")).toHaveText("Copied");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(example(name));
  }
  const download = page.waitForEvent("download");
  await page.getByTestId("download-holdings.csv").click();
  const d = await download;
  expect(d.suggestedFilename()).toBe("holdings.csv");
  expect(readFileSync(await d.path(), "utf8")).toBe(example("holdings.csv"));
});

test("import: a wrong header is refused with the expected header shown; a good file replaces the stored one", async ({ page }) => {
  await page.goto("/#/files");
  await page.getByTestId("import-ledger.csv").setInputFiles({ name: "ledger.csv", mimeType: "text/csv", buffer: Buffer.from("date,amount,note\n2026-01-01,1,x\n") });
  const refused = page.getByTestId("file-ledger.csv").getByRole("alert");
  await expect(refused).toContainText("Refused ledger.csv");
  await expect(refused).toContainText("Expected header: date,amount,currency,account,category,tags,note");
  await expect(refused).toContainText("First line: date,amount,note");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("absent");
  await page.getByTestId("import-many").setInputFiles(
    FILES.map((name) => ({ name, mimeType: "text/plain", buffer: Buffer.from(example(name)) })),
  );
  await expectCounts(page);
  await page.getByTestId("import-rates.csv").setInputFiles({ name: "r.csv", mimeType: "text/csv", buffer: Buffer.from([0x64, 0xff, 0x0a]) });
  await expect(page.getByTestId("file-rates.csv").getByRole("alert")).toContainText("not UTF-8");
  await page.getByTestId("paste-file").selectOption("rates.csv");
  await page.getByTestId("paste-text").fill("date,currency,rate\n2026-01-01,USD,0.385\n");
  await page.getByTestId("paste-use").click();
  await expect(page.getByTestId("count-rates.csv")).toHaveText("1 row");
});

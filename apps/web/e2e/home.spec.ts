import { expect, test } from "@playwright/test";

test("home page identifies ThreatSentinel and its development status", async ({ page }) => {
  await page.goto("/");

  await expect(page).toHaveTitle(/ThreatSentinel/);
  await expect(
    page.getByRole("heading", { name: "Security intelligence, with clarity." }),
  ).toBeVisible();
  await expect(page.getByText("Engineering foundation in progress")).toBeVisible();
});

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "yaml";
import { validateAndNormalizeConfigV1 } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const files = process.argv.slice(2);
if (!files.length) {
  console.error("Usage: node scripts/validate-config.mjs <config.yaml> [more...]");
  process.exit(2);
}

let hadError = false;
for (const file of files) {
  try {
    const fullPath = path.resolve(repoRoot, file);
    const text = await fs.readFile(fullPath, "utf8");
    const parsed = yaml.parse(text);
    validateAndNormalizeConfigV1(parsed);
    console.log(`OK: ${file}`);
  } catch (err) {
    hadError = true;
    console.error(`ERROR: ${file}`);
    console.error(String(err?.message || err));
  }
}

process.exit(hadError ? 1 : 0);

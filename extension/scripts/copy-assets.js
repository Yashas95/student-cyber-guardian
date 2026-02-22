// scripts/copy-assets.js
// Copies manifest.json, popup.html, and icons into dist/ after tsc compiles .ts files.

const fs   = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");          // extension/
const DIST = path.join(ROOT, "dist");
const SRC  = path.join(ROOT, "src");

if (!fs.existsSync(DIST)) fs.mkdirSync(DIST, { recursive: true });

// Files that live at the root of the extension folder
const rootFiles = ["manifest.json"];
for (const file of rootFiles) {
  const from = path.join(ROOT, file);
  const to   = path.join(DIST, file);
  if (fs.existsSync(from)) {
    fs.copyFileSync(from, to);
    console.log(`  copied  ${file}`);
  } else {
    console.warn(`  MISSING ${file} – make sure it is in extension/`);
  }
}

// popup.html lives in src/
const popupSrc = path.join(SRC, "popup.html");
const popupDst = path.join(DIST, "popup.html");
if (fs.existsSync(popupSrc)) {
  fs.copyFileSync(popupSrc, popupDst);
  console.log("  copied  popup.html");
} else {
  console.warn("  MISSING src/popup.html");
}

// Icons – copy whole icons/ folder if it exists at extension/icons/
const iconsSrc = path.join(ROOT, "icons");
const iconsDst = path.join(DIST, "icons");
if (fs.existsSync(iconsSrc)) {
  if (!fs.existsSync(iconsDst)) fs.mkdirSync(iconsDst);
  for (const f of fs.readdirSync(iconsSrc)) {
    fs.copyFileSync(path.join(iconsSrc, f), path.join(iconsDst, f));
    console.log(`  copied  icons/${f}`);
  }
} else {
  console.warn("  No icons/ folder found – Chrome needs icons to load the extension.");
  console.warn("  Place icon16.png, icon48.png, icon128.png inside extension/icons/");
}

console.log("\nBuild complete. Load the dist/ folder in Chrome.");

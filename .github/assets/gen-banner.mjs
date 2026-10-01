/**
 * Generates the ParleyPort banners (1600x500):
 *
 *   parleyport-banner.svg/.png       light, logo + "ParleyPort" + claim
 *   parleyport-banner-dark.svg/.png  dark,  logo + "ParleyPort" + claim
 *   parleyport-banner-logo.svg/.png  light, logo only, no text (support thread)
 *
 * The text-free variant is for an Unraid support thread, which takes a banner
 * without text.
 *
 * One logo serves both themes: the multi-tone frame and flag read on white
 * and on near-black alike.
 *
 * Text becomes SVG paths through opentype.js, so the SVG needs no font and
 * renders the same in resvg and a browser. Bree Serif for the name and Lato for
 * the claim, as in the other Bree Serif repos.
 *
 * Deps (global): opentype.js, @resvg/resvg-js. Fonts are fetched to the OS temp dir.
 * Run: node .github/assets/gen-banner.mjs
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";

const require = createRequire(import.meta.url);
const groot = execSync("npm root -g").toString().trim();
const opentype = require(`${groot}/opentype.js`);
const { Resvg } = require(`${groot}/@resvg/resvg-js`);

const __dir = dirname(fileURLToPath(import.meta.url));

const NAME = "ParleyPort";
const CLAIM = "Carries every word. Reads none of them.";
const W = 1600, H = 500;
const LOGO_FILE = "logo.svg";
const { vbW: LOGO_VB_W, vbH: LOGO_VB_H } = readViewBox(LOGO_FILE);
// The crest is about as wide as it is tall; 420 leaves 40px above and below.
const LH = 420, LW = LH * (LOGO_VB_W / LOGO_VB_H);
// The shared banner sizes: name 132, claim 44, logo gap 70, line gap 8.
const nameSize = 132, claimSize = 44, gap = 70, lineGap = 8;

const THEMES = [
  { suffix: "", bg: "#ffffff", name: "#1f2328", claim: "#5a5d5e" },
  { suffix: "-dark", bg: "#0d1117", name: "#e6edf3", claim: "#9aa4ad" },
];

function readViewBox(logoFile) {
  const raw = readFileSync(join(__dir, logoFile), "utf8");
  const m = raw.match(/viewBox="[\d.\-]+\s+[\d.\-]+\s+([\d.]+)\s+([\d.]+)"/);
  if (!m) throw new Error(`${logoFile}: no viewBox found`);
  return { vbW: parseFloat(m[1]), vbH: parseFloat(m[2]) };
}

const fontPath = join(tmpdir(), "ParleyPort-BreeSerif-Regular.ttf");
if (!existsSync(fontPath)) {
  const url = "https://github.com/google/fonts/raw/main/ofl/breeserif/BreeSerif-Regular.ttf";
  const res = await fetch(url);
  if (!res.ok) throw new Error(`font fetch ${res.status}`);
  writeFileSync(fontPath, Buffer.from(await res.arrayBuffer()));
}
const font = opentype.parse(readFileSync(fontPath));

const claimFontPath = join(tmpdir(), "ParleyPort-Lato-Regular.ttf");
if (!existsSync(claimFontPath)) {
  const r = await fetch("https://github.com/google/fonts/raw/main/ofl/lato/Lato-Regular.ttf");
  if (!r.ok) throw new Error(`claim font fetch ${r.status}`);
  writeFileSync(claimFontPath, Buffer.from(await r.arrayBuffer()));
}
const claimFont = opentype.parse(readFileSync(claimFontPath));

// Text layout (logo + name + claim, group centred horizontally).
const nameW = font.getAdvanceWidth(NAME, nameSize);
const claimW = claimFont.getAdvanceWidth(CLAIM, claimSize);
const groupW = LW + gap + Math.max(nameW, claimW);
const startX = Math.max(60, (W - groupW) / 2);
const LX = startX, LY = (H - LH) / 2;
const textX = startX + LW + gap;

const sc = (s) => s / font.unitsPerEm;
const nameAsc = font.ascender * sc(nameSize);
const nameDesc = -font.descender * sc(nameSize);
const claimAsc = claimFont.ascender * (claimSize / claimFont.unitsPerEm);
const blockH = nameAsc + nameDesc + lineGap + claimAsc;
const nameBaseline = H / 2 - blockH / 2 + nameAsc;
const claimBaseline = nameBaseline + nameDesc + lineGap + claimAsc;

const namePath = font.getPath(NAME, textX, nameBaseline, nameSize).toPathData(2);
const claimPath = claimFont.getPath(CLAIM, textX, claimBaseline, claimSize).toPathData(2);

// Embeds the logo at (x, y, w, h), keeping its own viewBox.
function embedLogo(logoFile, x, y, w, h) {
  const raw = readFileSync(join(__dir, logoFile), "utf8").replace(/<\?xml[^>]*\?>\s*/, "");
  const vb = (raw.match(/viewBox="([^"]+)"/) || [, `0 0 ${LOGO_VB_W} ${LOGO_VB_H}`])[1];
  return raw.replace(
    /<svg\b[^>]*>/,
    `<svg x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${w}" height="${h}" viewBox="${vb}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">`,
  );
}

function emit(name, svg, bg) {
  writeFileSync(join(__dir, `${name}.svg`), svg);
  const png = new Resvg(svg, { background: bg, fitTo: { mode: "width", value: W } }).render().asPng();
  writeFileSync(join(__dir, `${name}.png`), png);
  console.log(`wrote ${name}.svg + .png`);
}

for (const t of THEMES) {
  const full = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <rect width="${W}" height="${H}" fill="${t.bg}"/>
  ${embedLogo(LOGO_FILE, LX, LY, LW, LH)}
  <path d="${namePath}" fill="${t.name}"/>
  <path d="${claimPath}" fill="${t.claim}"/>
</svg>
`;
  emit(`parleyport-banner${t.suffix}`, full, t.bg);
}

const logoLX = (W - LW) / 2, logoLY = (H - LH) / 2;
const lt = THEMES[0];
const logoOnly = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <rect width="${W}" height="${H}" fill="${lt.bg}"/>
  ${embedLogo(LOGO_FILE, logoLX, logoLY, LW, LH)}
</svg>
`;
emit("parleyport-banner-logo", logoOnly, lt.bg);

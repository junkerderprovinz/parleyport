/**
 * Generates icon.svg and icon.png (512x512): the logo on the #161616 square of
 * the KnightLoader app icon. The Community Apps tile and the Docker Hub avatar
 * use it; a solid background keeps the light flag visible on Unraid's light
 * theme.
 *
 * Deps (global): @resvg/resvg-js. Run: node .github/assets/gen-icon.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";

const require = createRequire(import.meta.url);
const { Resvg } = require(`${execSync("npm root -g").toString().trim()}/@resvg/resvg-js`);
const __dir = dirname(fileURLToPath(import.meta.url));

const S = 1024, PAD = 150;
const raw = readFileSync(join(__dir, "logo.svg"), "utf8").replace(/<\?xml[^>]*\?>\s*/, "");
const [, , vbW, vbH] = raw.match(/viewBox="([^"]+)"/)[1].split(/\s+/).map(Number);
const w = S - 2 * PAD, h = w * (vbH / vbW);
const logo = raw.replace(
  /<svg\b[^>]*>/,
  `<svg x="${PAD}" y="${((S - h) / 2).toFixed(1)}" width="${w}" height="${h.toFixed(1)}" viewBox="0 0 ${vbW} ${vbH}" xmlns="http://www.w3.org/2000/svg">`,
);
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${S}" height="${S}" viewBox="0 0 ${S} ${S}">
  <rect width="${S}" height="${S}" fill="#161616"/>
  ${logo}
</svg>
`;
writeFileSync(join(__dir, "icon.svg"), svg);
writeFileSync(join(__dir, "icon.png"), new Resvg(svg, { fitTo: { mode: "width", value: 512 } }).render().asPng());
console.log("wrote icon.svg + icon.png");

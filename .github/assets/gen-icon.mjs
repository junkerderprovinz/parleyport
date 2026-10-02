/**
 * Generates icon.svg and icon.png (512x512): the logo on a transparent square,
 * centred. The Community Apps listing shows the bare logo; its multi-tone
 * frame and shaded flag read on Unraid's light and dark themes alike.
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

const raw = readFileSync(join(__dir, "logo.svg"), "utf8").replace(/<\?xml[^>]*\?>\s*/, "");
const [, , w, h] = raw.match(/viewBox="([^"]+)"/)[1].split(/\s+/).map(Number);
const S = Math.max(w, h);
const logo = raw.replace(
  /<svg\b[^>]*>/,
  `<svg x="${(S - w) / 2}" y="${(S - h) / 2}" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg">`,
);
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${S}" height="${S}" viewBox="0 0 ${S} ${S}">
  ${logo}
</svg>
`;
writeFileSync(join(__dir, "icon.svg"), svg);
writeFileSync(join(__dir, "icon.png"), new Resvg(svg, { fitTo: { mode: "width", value: 512 } }).render().asPng());
console.log("wrote icon.svg + icon.png");

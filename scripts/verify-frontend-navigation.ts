import fs from "fs";
import path from "path";

const appPath = path.join(__dirname, "..", "frontend", "src", "App.jsx");
const source = fs.readFileSync(appPath, "utf8");

const fail = (message: string) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const findNavItemBlock = (id: string) => {
  const re = new RegExp(String.raw`\{[^}]*id:\s*"${id}"[^}]*\}`, "m");
  return source.match(re)?.[0] || "";
};

const allNavStart = source.indexOf("const allNav = [");
const allNavEnd = source.indexOf("];", allNavStart);
if (allNavStart === -1 || allNavEnd === -1) fail("No se pudo localizar allNav en App.jsx");

const allNavBlock = source.slice(allNavStart, allNavEnd);

const vulnsItem = findNavItemBlock("vulns");
if (!vulnsItem) fail('Falta el menú principal id: "vulns"');
if (!vulnsItem.includes('label: "Catálogo de vulnerabilidades"')) {
  fail('El menú "vulns" debe llamarse "Catálogo de vulnerabilidades"');
}

const exploitedItem = findNavItemBlock("exploited");
if (!exploitedItem) fail('Falta el menú id: "exploited"');
if (!exploitedItem.includes('label: "Explotación CVE"')) {
  fail('El menú "exploited" debe llamarse "Explotación CVE"');
}
if (exploitedItem.includes('parent:')) {
  fail('El menú "exploited" debe ser de primer nivel (sin parent)');
}

const vulnsIdx = allNavBlock.indexOf('id: "vulns"');
const exploitedIdx = allNavBlock.indexOf('id: "exploited"');
if (vulnsIdx === -1 || exploitedIdx === -1) fail("No se pudieron localizar los ids en allNav");
if (exploitedIdx < vulnsIdx) fail('El menú "exploited" no puede ir antes que "vulns"');

process.stdout.write("OK\n");

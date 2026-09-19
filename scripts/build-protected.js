const fs = require('fs');
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'dist-protected');
const excluded = new Set(['public', 'landing', 'data', 'node_modules', 'dist-protected', 'scripts']);
const excludedFilePrefixes = ['tmp-'];

fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });

function copyServerFiles(source, target, relative = '') {
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    if (!relative && excluded.has(entry.name)) continue;
    const sourcePath = path.join(source, entry.name);
    const targetPath = path.join(target, entry.name);
    const relativePath = path.join(relative, entry.name);
    if (entry.isDirectory()) {
      fs.mkdirSync(targetPath, { recursive: true });
      copyServerFiles(sourcePath, targetPath, relativePath);
    } else if (entry.name.endsWith('.js')) {
      const code = fs.readFileSync(sourcePath, 'utf8');
      const protectedCode = JavaScriptObfuscator.obfuscate(code, {
        compact: true,
        controlFlowFlattening: false,
        deadCodeInjection: false,
        identifierNamesGenerator: 'hexadecimal',
        renameGlobals: false,
        rotateStringArray: true,
        selfDefending: false,
        stringArray: true,
        stringArrayThreshold: 0.6,
      }).getObfuscatedCode();
      fs.writeFileSync(targetPath, protectedCode);
    } else {
      fs.copyFileSync(sourcePath, targetPath);
    }
  }
}

function copyDirectory(name) {
  fs.cpSync(path.join(root, name), path.join(output, name), { recursive: true });
}

copyServerFiles(root, output);
copyDirectory('public');
copyDirectory('landing');
fs.copyFileSync(path.join(root, 'package.json'), path.join(output, 'package.json'));
console.log(`Protected build created at ${output}`);

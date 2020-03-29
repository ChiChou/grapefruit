#!/usr/bin/env node
const fs = require('fs').promises;
const path = require('path');

// cmodule preprocessor
async function c() {
  const folder = path.join(__dirname, '..', 'src', 'c');
  const output = path.join(__dirname, '..', 'gen');
  const files = await fs.readdir(folder);
  for (let file of files.filter(file => path.parse(file).ext === '.c')) {
    const raw = await fs.readFile(path.join(folder, file));
    const str = JSON.stringify(raw.toString('utf8'));
    const abs = path.join(output, `${file}.ts`);
    await fs.writeFile(abs, 'export default ' + str);
  }
}

c();

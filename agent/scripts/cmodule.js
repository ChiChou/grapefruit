#!/usr/bin/env node
import { promises as fs } from 'fs';
import { join, parse } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

// cmodule preprocessor
async function c() {
  const folder = join(__dirname, '..', 'src', 'c');
  const output = join(__dirname, '..', 'gen');
  const files = await fs.readdir(folder);
  try {
    await fs.stat(output);
  } catch(e) {
    fs.mkdir(output);
  }
  
  for (let file of files.filter(file => parse(file).ext === '.c')) {
    const raw = await fs.readFile(join(folder, file));
    const str = JSON.stringify(raw.toString('utf8'));
    const abs = join(output, `${file}.ts`);
    await fs.writeFile(abs, 'export default ' + str);
  }
}

c();

#!/usr/bin/env node

import { fileURLToPath } from 'url';
import { promises as fs } from 'fs';
import { join, parse } from 'path';
import { EOL } from 'os';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

// rpc modules
async function rpc() {
  const folder = join(__dirname, '..', 'src', 'modules');
  const files = await fs.readdir(folder);
  const index = join(folder, 'index.ts');

  function* gen() {
    const registry = files
      .filter(name => name !== 'index.ts')
      .map(parse)
      .filter(e => e.ext === '.ts')
      .map(e => e.name)

    for (let name of registry) {
      yield `import * as ${name} from './${name}.js'`;
    }
    yield ''
    yield `export default { ${registry.join(', ')} }`
  }

  await fs.writeFile(index, [...gen()].join(EOL));
}

rpc();

#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const os = require('os');

// rpc modules
async function rpc() {
  const folder = path.join(__dirname, '..', 'src', 'modules');
  const files = await fs.readdir(folder);
  const index = path.join(folder, 'index.ts');

  function* gen() {
    const registry = files
      .filter(name => name !== 'index.ts')
      .map(path.parse)
      .filter(e => e.ext === '.ts')
      .map(e => e.name)

    for (let name of registry) {
      yield `import * as ${name} from './${name}.js'`;
    }
    yield ''
    yield `export default { ${registry.join(', ')} }`
  }

  await fs.writeFile(index, [...gen()].join(os.EOL));
}

rpc();

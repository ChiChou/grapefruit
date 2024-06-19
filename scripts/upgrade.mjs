import { readFileSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

for (const child of ['guiv3', 'server', 'agent', '.']) {
    const cwd = join(__dirname, '..', child);
    const content = readFileSync(join(cwd, 'package.json'), 'utf8');
    const json = JSON.parse(content);
    const keysAndFlags = {
        dependencies: '--save',
        devDependencies: '--save-dev'
    };

    for (let key in keysAndFlags) {
        if (!json[key])
            continue;

        const names = Object.keys(json[key]).map(name => `${name}@latest`);
        if (!names.length)
            continue;

        console.log('upgrade', key);
        console.log(names);

        spawnSync('npm', ['install', ...names, keysAndFlags[key]], { stdio: 'inherit', cwd });
    }

    spawnSync('npm', ['audit', 'fix'], { stdio: 'inherit', cwd });
}
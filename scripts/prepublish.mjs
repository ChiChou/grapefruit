import { execSync } from 'child_process';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

for (const child of ['guiv3', 'server', 'agent']) {
  const cwd = join(__dirname, '..', child)
  execSync('npm run build', { cwd, stdio: 'inherit' })
}

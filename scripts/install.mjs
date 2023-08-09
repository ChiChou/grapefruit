import { spawn } from 'child_process';
import { promises as fsp } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

async function main() {
  try {
    await fsp.access('.gitignore', fs.constants.F_OK);
  } catch(_) {
    // production
    return
  }

  const tasks = ['guiv3', 'server', 'agent'].map(child => {
    const cwd = join(__dirname, '..', child);
    return new Promise((resolve, reject) => {
      const child = spawn('npm', ['i'], { cwd, stdio: 'inherit' });
      child.on('close', code => {
        if (code !== 0) {
          reject(new Error(`child process exited with code ${code}`));
        } else {
          resolve();
        }
      })
    })
  })

  return Promise.all(tasks);
}

main()
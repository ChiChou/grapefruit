import { execSync, spawn, spawnSync } from 'child_process';
import { join } from 'path';
import { platform } from 'os';
import { fileURLToPath } from 'url';

const isWindows = platform() === 'win32';
const __dirname = fileURLToPath(new URL('.', import.meta.url));

const env = Object.assign({}, process.env, { NODE_ENV: 'development' });

function* tasks() {
  const spec = {
    guiv3: ['run', 'dev'],
    agent: ['run', 'watch'],
    server: ['run', 'dev']
  };

  for (const [name, args] of Object.entries(spec)) {
    const cwd = join(__dirname, '..', name);
    yield [args, cwd];
  }
}

function tryRun(cmd) {
  try {
    return execSync(cmd).toString().trim();
  } catch (_) {

  }
}

function tmux() {
  const argv = ['new-session'];
  for (const [args, cwd] of tasks()) {
    argv.push('-c', cwd, 'npm');
    argv.push(...args);
    argv.push(';', 'split-window', '-h')
  }
  // last split-window
  argv.pop();
  argv.pop();
  // C-a space
  argv.push('next-layout');

  spawnSync('tmux', argv, { stdio: 'inherit', env });
}

function wt() {
  const argv = [];
  for (const [args, cwd] of tasks()) {
    argv.push('-d', cwd, 'cmd', '/c', 'npm')
    argv.push(...args)
    argv.push(';', 'new-tab')
  }
  argv.push('cmd', '-c', 'echo OK')
  spawn('wt', argv, { env })
  process.exit() // detach
}

if (isWindows) {
  if (tryRun('where wt')) {
    wt()
  } else {
    console.error('Windows Terminal not found. Please install it from Microsoft Store');
  }
} else {
  if (tryRun('which tmux')) {
    tmux()
  } else {
    console.error('tmux not found. Please install it first');
  }
}

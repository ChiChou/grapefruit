import { execSync, spawn, spawnSync } from 'child_process';
import { join } from 'path';
import { platform } from 'os';
import { fileURLToPath } from 'url';

const isWin = platform() === 'win32';
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

function platformize(tool, args) {
  let bin = tool;
  let joint = args;
  if (isWin) {
    bin = 'cmd.exe';
    joint = ['/c', tool, ...args];
  }
  return [bin, joint];
}

function run() {
  if (isWin) {
    console.error('Windows platform is not supported. You should manually start 3 terminals, or install Windows Terminal from Microsoft Store');
    console.error(`It's gonna be a mess here`);
  }

  function handler() {
    console.log('❌child process disconected');
    process.exit();
  }

  const children = []
  for (const [args, cwd] of tasks()) {
    const [bin, argv] = platformize('npm', args);
    const p = spawn(bin, argv, { stdio: 'inherit', cwd, env });
    p.on('disconnect', handler);
  }

  process.on('SIGINT', () => children.filter(p => pid).forEach(p => p.kill()));
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

if (isWin && tryRun('where wt')) {
  wt()
} else if (tryRun('which tmux')) {
  tmux()
} else {
  // crappy terminal
  run(tasks())
}

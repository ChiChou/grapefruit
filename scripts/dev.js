const cp = require('child_process');
const path = require('path');
const { platform } = require('os');

const isWin = platform() === 'win32'

const env = Object.assign({}, process.env, { NODE_ENV: 'development', NODE_OPTIONS: '--openssl-legacy-provider' })

function* tasks() {
  const spec = {
    gui: ['run', 'serve'],
    agent: ['run', 'watch'],
    server: ['run', 'dev']
  };

  for (let [name, args] of Object.entries(spec)) {
    const cwd = path.join(__dirname, '..', name);
    yield [args, cwd];
  }
}

function tryRun(cmd) {
  try {
    return cp.execSync(cmd).toString().trim();
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
  for (let [args, cwd] of tasks()) {
    const [bin, argv] = platformize('npm', args);
    const p = cp.spawn(bin, argv, { stdio: 'inherit', cwd, env });
    p.on('disconnect', handler);
  }

  process.on('SIGINT', () => children.filter(p => pid).forEach(p => p.kill()));
}

function tmux() {
  const argv = ['new-session'];
  for (let [args, cwd] of tasks()) {
    argv.push('-c', cwd, 'npm');
    argv.push(...args);
    argv.push(';', 'split-window', '-h')
  }
  // last split-window
  argv.pop();
  argv.pop();
  // C-a space
  argv.push('next-layout');

  cp.spawnSync('tmux', argv, { stdio: 'inherit', env });
}

function wt() {
  const argv = [];
  for (let [args, cwd] of tasks()) {
    argv.push('-d', cwd, 'cmd', '/c', 'npm')
    argv.push(...args)
    argv.push(';', 'new-tab')
  }
  argv.push('cmd', '-c', 'echo OK')
  cp.spawn('wt', argv, { env })
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

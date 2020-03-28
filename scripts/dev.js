const cp = require('child_process')
const path = require('path')


function *tasks() {
  const spec = {
    gui: ['run', 'serve'],
    agent: ['run', 'watch']
  }

  for (let [name, args] of Object.entries(spec)) {
    const cwd = path.join(__dirname, '..', name)
    yield [args, cwd]
  }
}

function findTmux() {
  try {
    return cp.execSync('which tmux').toString().trim()
  } catch(_) {

  }
}

const location = findTmux()
if (location) {
  tmux(location, tasks())
} else {
  run(tasks())
}

function run(queue) {
  function handler() {
    console.log('❌child process disconected')
    process.exit()
  }

  const children = []
  for (let [args, cwd] of queue) {
    const p = cp.spawn('npm', args, { stdio: 'inherit', cwd })
    p.on('disconnect', handler)
  }

  process.on('SIGINT', () => children.filter(p => pid).forEach(p => p.kill()))
}

function tmux(location, queue) {
  const argv = ['new-session']
  for (let [args, cwd] of queue) {
    argv.push('-c', cwd, 'npm')
    argv.push(...args)
    argv.push(';', 'split-window')
  }
  // remove last split-window
  argv.pop()
  // C-a space
  argv.push('next-layout')

  cp.spawnSync(location, argv, { stdio: 'inherit' })
}


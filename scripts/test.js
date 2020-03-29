const cp = require('child_process')
const path = require('path')

const cwd = path.join(__dirname, '..', 'server')
try {
  cp.execSync('npm test', { cwd, stdio: 'inherit' })
} catch(_) {
  console.error('test failed')
}
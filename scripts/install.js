const cp = require('child_process')
const path = require('path')


for (let child of ['gui', 'server', 'agent']) {
  const cwd = path.join(__dirname, '..', child)
  cp.execSync('cnpm i', { cwd, stdio: 'inherit' })
}

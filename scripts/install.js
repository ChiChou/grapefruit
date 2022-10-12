const cp = require('child_process')
const fs = require('fs')
const path = require('path')

function main() {
  try {
    fs.accessSync('.gitignore', fs.constants.F_OK)
  } catch(_) {
    // production
    cp.execSync('node server/dist/scripts/migrate.js')
    return
  }
 
  for (let child of ['gui', 'server', 'agent']) {
    const cwd = path.join(__dirname, '..', child)
    cp.execSync('npm i --force', { cwd, stdio: 'inherit' })
  }
}

main()
import { execSync } from 'child_process'
import { accessSync, constants } from 'fs'
import { join } from 'path'

function main() {
  try {
    accessSync('.gitignore', constants.F_OK)
  } catch(_) {
    // production
    execSync('node server/dist/scripts/migrate.js')
    return
  }
 
  for (let child of ['guiv3', 'server', 'agent']) {
    const cwd = join(__dirname, '..', child)
    execSync('npm i', { cwd, stdio: 'inherit' })
  }
}

main()
import { execSync } from 'child_process'
import { join } from 'path'

for (const child of ['gui', 'server', 'agent']) {
  const cwd = join(__dirname, '..', child)
  execSync('npm run build', { cwd, stdio: 'inherit' })
}

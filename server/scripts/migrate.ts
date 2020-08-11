import { spawn } from 'child_process'

import { setup } from '../lib/workspace'
import { env } from '../lib/db'


async function main(): Promise<void> {
  await setup()
  const envp = Object.assign({}, process.env, env())

  let action = 'run', rest = []
  if (process.argv.length > 2) {
    [action, ...rest] = process.argv.slice(2)
  }

  const args = ['ts-node', 'node_modules/typeorm/cli.js', `migration:${action}`, ...rest]
  spawn('npx', args, { shell: true, stdio: 'inherit', env: envp })
}

main()
import * as path from 'path'
import * as os from 'os'
import { promises as fsp } from 'fs'


export function home(): string {
  const name = 'grapefruit'

  if (process.platform === 'darwin')
    return path.join(os.homedir(), 'Library', 'Application Support', name)

  if (process.platform === 'win32')
    return path.join(process.env.APPDATA, name)

  return path.join(os.homedir(), '.local', 'share', name)
}

export function concat(...args: string[]): string {
  return path.join(home(), ...args)
}

export async function setup(): Promise<void> {
  const cwd = home()
  try {
    await fsp.access(cwd)
  } catch(e) {
    await fsp.mkdir(cwd, { recursive: true })
  }

  const scripts = path.join(cwd, 'scripts')
  await fsp.mkdir(scripts)
  await fsp.writeFile(path.join(scripts, 'hello.js'), `'hello ' + Process.id`)
}

export async function cleanup(): Promise<void> {
  return fsp.rmdir(home(), { recursive: true })
}
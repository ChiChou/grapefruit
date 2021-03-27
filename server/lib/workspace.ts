import * as path from 'path'
import * as os from 'os'
import { promises as fsp, constants } from 'fs'


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

async function mkdirp(dir: string): Promise<void> {
  try {
    await fsp.access(dir)
  } catch(e) {
    await fsp.mkdir(dir, { recursive: true })
  }
}

export async function setup(): Promise<void> {
  const cwd = home()
  await mkdirp(cwd)
  const scripts = path.join(cwd, 'scripts')
  await mkdirp(scripts)
  await fsp.writeFile(path.join(scripts, 'hello.js'), `'hello ' + Process.id`)
}

export async function cleanup(): Promise<void> {
  return fsp.rmdir(home(), { recursive: true })
}
import path from 'path'
import os from 'os'


export function home(): string {
  if (process.platform === 'darwin')
    return path.join(os.homedir(), 'Library', 'Application Support', 'grapefruit')

  if (process.platform === 'win32')
    return path.join(process.env.APPDATA, 'grapefruit')

  return path.join(os.homedir(), '.local', 'share', 'grapefruit')
}

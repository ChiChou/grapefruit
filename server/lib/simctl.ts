import cp from 'child_process'
import path from 'path'
import fs from 'fs'
import os from 'os'

import { promisify } from 'util'
import { Apps, ListResult, SimAppInfo, SimulatorInfo } from '../api/sim'

const OPT = { timeout: 3000 }

const exec = promisify(cp.execFile)

function* available(result: ListResult) {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for (const [runtimeId, models] of Object.entries(result.devices)) {
    for (const model of models) {
      if (model.isAvailable && model.state === 'Booted') {
        const { deviceTypeIdentifier, state, name, udid } = model
        yield { deviceTypeIdentifier, state, name, udid }
      }
    }
  }
}

export async function simulators(): Promise<SimulatorInfo[]> {
  if (process.platform != 'darwin') return Promise.resolve([])

  const { stdout } = await exec('/usr/bin/xcrun', ['simctl', 'list', 'devices', '--json'], OPT)
  const result: ListResult = JSON.parse(stdout)
  return [...available(result)]
}

export async function launch(udid: string, bundle: string): Promise<number> {
  const { stdout } = await exec('/usr/bin/xcrun', ['simctl', 'launch', udid, bundle], OPT)
  return parseInt(stdout.substring(`${bundle}: `.length), 10)
}

export async function findRunning(udid: string, bundle: string): Promise<number> {
  const { stdout } = await exec('/usr/bin/xcrun', ['simctl', 'spawn', udid, 'launchctl', 'list'], OPT)
  for (const line of stdout.split(os.EOL)) {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const [pid, status, label] = line.split('\t')
    if (label.startsWith(`UIKitApplication:${bundle}`)) {
      return parseInt(pid, 10)
    }
  }

  return Promise.reject(new Error(`${bundle} is not running`))
}

async function appsInternal(udid: string): Promise<Apps> {
  if (process.platform != 'darwin') return Promise.resolve({})
  if (!/^[a-f\d-]+$/i.test(udid)) return Promise.reject(new Error(`invalid udid`))

  const simctl = cp.spawn('/usr/bin/xcrun', ['simctl', 'listapps', udid])
  const plutil = cp.spawn('/usr/bin/plutil', ['-convert', 'json', '-r', '-o', '-', '--', '-'])
  
  return new Promise<Apps>((resolve, reject) => {
    const chunks = []
    plutil.stdout.on('data', chunk => chunks.push(chunk))
    plutil
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      .once('exit', (code, sig) => {
        if (code !== 0)
          reject(new Error(`process exited with code ${code}`))
        else
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      })
      .once('error', reject)
    simctl.stdout.pipe(plutil.stdin)

    setTimeout(() => {
      reject(new Error('execution timed out'))
      plutil.kill()
      simctl.kill()
    }, 3000)
  })
}

export async function apps(udid: string): Promise<SimAppInfo[]> {
  const result = []
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for (const [bundle, app] of Object.entries(await appsInternal(udid))) {
    if (app.ApplicationType === 'User') {
      const { CFBundleDisplayName, CFBundleExecutable, CFBundleIdentifier, CFBundleName, CFBundleVersion } = app
      result.push({ CFBundleDisplayName, CFBundleExecutable, CFBundleIdentifier, CFBundleName, CFBundleVersion })
    }
  }
  return result
}

async function iconFromApp(root: string) {
  const plist = path.join(root, 'Info.plist')
  const iconName = await new Promise((resolve, reject) => {
    cp.execFile('/usr/bin/plutil', ['-convert', 'json', '-o', '-', plist], OPT, (err, stdout) => {
      if (err) {
        reject(err)
      } else {
        const info = JSON.parse(stdout)
        try {
          const { CFBundleIconFiles } = info.CFBundleIcons.CFBundlePrimaryIcon
          resolve(CFBundleIconFiles.pop())
        } catch (e) {
          reject(new Error('Info.plist does not specify an icon'))
        }
      }
    })
  })

  return (async () => {
    const suffixes = ['', '@2x', '@3x']
    for (const suffix of suffixes) {
      const filename = path.join(root, `${iconName}${suffix}.png`)
      try {
        await fs.promises.access(filename, fs.constants.F_OK)
        return filename
      } catch (e) {
        continue
      }
    }

    throw new Error('icon not found')
  })()
}

export async function icon(udid: string, bundle: string): Promise<string> {
  for (const [id, app] of Object.entries(await appsInternal(udid))) {
    if (id === bundle) {
      const original = await iconFromApp(app.Path)
      const cached = path.join(os.tmpdir(), `${udid}-${bundle}.png`)
      try {
        await fs.promises.access(cached, fs.constants.F_OK)
        return cached
      // eslint-disable-next-line no-empty
      } catch(_) {

      }

      // convert
      return new Promise((resolve, reject) => {
        cp.execFile('/usr/bin/xcrun', ['-sdk', 'iphoneos', 'pngcrush', '-revert-iphone-optimizations', original, cached], err => {
          if (err) {
            reject(new Error('failed to convert png format'))
          } else {
            resolve(cached)
          }
        })
      })
    }
  }

  return Promise.reject(new Error(`bundle ${bundle} not found`))
}

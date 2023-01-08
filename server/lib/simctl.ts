import cp from 'child_process'
import path from 'path'
import fs from 'fs'
import os from 'os'

type SimulatorState = 'Shutdown' | 'Booted'
type AppType = 'User' | 'System'

interface RuntimeInfo {
  availabilityError?: string;
  dataPath: string;
  dataPathSize: number;
  logPath: string;
  udid: string;
  isAvailable: boolean;
  deviceTypeIdentifier: string;
  state: SimulatorState;
  name: string;
}

interface ListResult {
  devices: { [name: string]: RuntimeInfo[] };
}

interface SimAppInfo {
  ApplicationType: AppType;
  Bundle: string;
  CFBundleDisplayName: string;
  CFBundleExecutable: string;
  CFBundleIdentifier: string;
  CFBundleName: string;
  CFBundleVersion: string;
  DataContainer: string;
  Path: string;
  GroupContainers: { [groupID: string]: string };
}

interface Apps {
  [bundle: string]: SimAppInfo
}

export interface SimulatorInfo {
  deviceTypeIdentifier: string;
  state: SimulatorState;
  name: string;
  udid: string;
}

function* available(result: ListResult) {
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

  const result: ListResult = await new Promise((resolve, reject) => {
    cp.execFile('/usr/bin/xcrun', ['simctl', 'list', 'devices', '--json'], (err, stdout, stderr) => {
      if (err) {
        process.stderr.write(stderr)
        console.error(err)
        reject(err)
      } else {
        resolve(JSON.parse(stdout))
      }
    })
  })

  return [...available(result)]
}

export async function launch(udid: string, bundle: string): Promise<number> {
  return new Promise((resolve, reject) => {
    cp.execFile('/usr/bin/xcrun', ['simctl', 'launch', udid, bundle], (err, stdout, stderr) => {
      if (err) {
        reject(err)
      } else {
        const pid = parseInt(stdout.substring(`${bundle}: `.length), 10)
        resolve(pid)
      }
    })
  })
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
      .once('exit', (code, sig) => {
        if (code !== 0)
          reject(new Error(`process exited with code ${code}`))
        else
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      })
      .once('error', reject)
    simctl.stdout.pipe(plutil.stdin)
  })
}

export async function apps(udid: string): Promise<SimAppInfo[]> {
  const result = []
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
    cp.execFile('/usr/bin/plutil', ['-convert', 'json', '-o', '-', plist], (err, stdout, stderr) => {
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

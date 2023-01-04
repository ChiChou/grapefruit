import cp from 'child_process'

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
      if (err)
        reject(err)

      const pid = parseInt(stdout.substring(`${bundle}: `.length), 10)
      resolve(pid)
    })
  })
}

export async function apps(udid: string): Promise<SimAppInfo[]> {
  if (process.platform != 'darwin') return Promise.resolve([])
  if (!/^[a-f\d-]+$/i.test(udid)) return Promise.reject(new Error(`invalid udid`))

  const simctl = cp.spawn('/usr/bin/xcrun', ['simctl', 'listapps', udid])
  const plutil = cp.spawn('/usr/bin/plutil', ['-convert', 'json', '-r', '-o', '-', '--', '-'])

  const apps = await new Promise<Apps>((resolve, reject) => {
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

  const result = []
  for (const [bundle, app] of Object.entries(apps)) {
    if (app.ApplicationType === 'User') {
      const { CFBundleDisplayName, CFBundleExecutable, CFBundleIdentifier, CFBundleName, CFBundleVersion } = app
      result.push({ CFBundleDisplayName, CFBundleExecutable, CFBundleIdentifier, CFBundleName, CFBundleVersion })
    }
  }

  return result
}

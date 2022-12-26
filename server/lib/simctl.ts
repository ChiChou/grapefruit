import cp from 'child_process'

type State = 'Shutdown' | 'Booted'
type AppType = 'User' | 'System'

interface Model {
  availabilityError?: string;
  dataPath: string;
  dataPathSize: number;
  logPath: string;
  udid: string;
  isAvailable: boolean;
  deviceTypeIdentifier: string;
  state: State;
  name: string;
}

interface ListResult {
  devices: { [name: string]: Model[] };
}

interface App {
  ApplicationType: AppType;
  Bundle: string;
  CFBundleDisplayName: string;
  CFBundleExecutable: string;
  CFBundleIdentifier: string;
  DataContainer: string;
  Path: string;
  GroupContainers: { [groupID: string]: string };
}

interface Apps {
  [bundle: string]: App
}

interface Simulator {
  deviceTypeIdentifier: string;
  state: State;
  name: string;
  udid: string;
}

function runAndParseJSON(cmd: string) {
  return new Promise((resolve, reject) => {
    cp.exec(cmd, (err, stdout, stderr) => {
      if (err) {
        console.error(err)
        reject(err)
      } else {
        resolve(JSON.parse(stdout))
      }
    })
  })
}

const knownUDIDCache = new Set()

function* available(result: ListResult) {
  for (const [runtimeId, models] of Object.entries(result.devices)) {
    for (const model of models) {
      if (model.isAvailable && model.state === 'Booted') {
        const { deviceTypeIdentifier, state, name, udid } = model
        knownUDIDCache.add(udid)
        yield { deviceTypeIdentifier, state, name, udid }
      }
    }
  }
}

export async function simulators(): Promise<Simulator[]> {
  if (process.platform != 'darwin') return Promise.resolve([])

  const result = (await runAndParseJSON('xcrun simctl list devices --json')) as ListResult
  knownUDIDCache.clear()
  return [...available(result)]
}

export async function apps(udid: string): Promise<Apps> {
  if (process.platform != 'darwin') return Promise.resolve({})

  const sanitized = knownUDIDCache.has(udid) ? udid : 'booted'
  const cmd = `xcrun simctl listapps ${sanitized} | plutil -convert json -r -o - -- -`
  return runAndParseJSON(cmd) as Promise<Apps>
}

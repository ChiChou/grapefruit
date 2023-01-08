type SimulatorState = 'Shutdown' | 'Booted'
type AppType = 'User' | 'System'

export interface RuntimeInfo {
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

export interface SimulatorInfo {
  deviceTypeIdentifier: string;
  state: SimulatorState;
  name: string;
  udid: string;
}

export interface ListResult {
  devices: { [name: string]: RuntimeInfo[] };
}

export interface SimAppInfo {
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

export interface Apps {
  [bundle: string]: SimAppInfo
}
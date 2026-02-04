export interface Device {
  id: string;
  type: "usb" | "local" | "remote";
  removable: boolean;
  name: string;
}

export interface Application {
  name: string;
  identifier: string;
  pid: number;
}

export interface Process {
  name: string;
  pid: number;
}

export interface DeviceInfo {
  arch: string;
  os: {
    version: string;
    id: string;
    name: string;
  };
  udid: string;
  platform: string;
  name: string;
  access: string;
  interfaces?: Array<{
    type: string;
    address: string;
  }>;
}

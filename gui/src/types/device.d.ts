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

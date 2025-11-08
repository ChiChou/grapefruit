export interface Device {
  name: string;
  id: string;
  type: string;
  removable: boolean;
}

export interface Application {
  name: string;
  identifier: string;
  pid: number;
}

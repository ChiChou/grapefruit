import frida, { type Device, type Application, type Process } from "./xvii.ts";

interface SerializedDevice {
  id: string;
  type: "usb" | "local" | "remote";
  removable: boolean;
  name: string;
}

interface SerializedApp {
  name: string;
  identifier: string;
  pid: number;
}

interface SerializedProcess {
  name: string;
  pid: number;
  path?: string;
  user?: string;
  ppid?: number;
  started?: string;
}

function isRemovable(dev: Device): boolean {
  return dev.type === frida.DeviceType.Remote && dev.name !== "Local Socket";
}

export function device(dev: Device): SerializedDevice {
  const { name, id, type } = dev;
  return {
    name,
    id,
    type,
    removable: isRemovable(dev),
  };
}

export function app(app: Application): SerializedApp {
  const { name, identifier, pid } = app;
  return {
    name,
    identifier,
    pid,
  };
}

export function process(proc: Process): SerializedProcess {
  const { name, pid, parameters } = proc;
  const params = parameters as {
    path?: string;
    user?: string;
    ppid?: number;
    started?: string;
  };
  return {
    name,
    pid,
    path: params.path,
    user: params.user,
    ppid: params.ppid,
    started: params.started,
  };
}

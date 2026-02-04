import frida, { type Device, type Application, type Process } from "./xvii.ts";

import type {
  Device as DeviceSchema,
  Application as ApplicationSchema,
  Process as ProcessSchema,
} from "@shared/schema.d.ts";

function isRemovable(dev: Device): boolean {
  return dev.type === frida.DeviceType.Remote && dev.name !== "Local Socket";
}

export function device(dev: Device): DeviceSchema {
  const { name, id, type } = dev;
  return {
    name,
    id,
    type,
    removable: isRemovable(dev),
  };
}

export function app(app: Application): ApplicationSchema {
  const { name, identifier, pid } = app;
  return {
    name,
    identifier,
    pid,
  };
}

export function process(proc: Process): ProcessSchema {
  const { name, pid } = proc;
  return {
    name,
    pid,
  };
}

import ObjC from "frida-objc-bridge";

export interface UIDeviceInfo {
  name: string;
  model: string;
  localizedModel: string;
  systemName: string;
  systemVersion: string;
  identifierForVendor: string;
  batteryLevel: number;
  batteryState: string;
  userInterfaceIdiom: string;
  isMultitaskingSupported: boolean;
}

const BATTERY_STATES: Record<number, string> = {
  0: "Unknown",
  1: "Unplugged",
  2: "Charging",
  3: "Full",
};

const UI_IDIOMS: Record<number, string> = {
  0: "Phone",
  1: "Pad",
  2: "TV",
  3: "CarPlay",
  4: "Mac",
  5: "Vision",
};

export function info(): UIDeviceInfo {
  const device = ObjC.classes.UIDevice.currentDevice();

  // Enable battery monitoring so batteryLevel / batteryState return real values
  device.setBatteryMonitoringEnabled_(true);

  const batteryStateRaw: number = device.batteryState();
  const idiomRaw: number = device.userInterfaceIdiom();

  return {
    name: device.name().toString(),
    model: device.model().toString(),
    localizedModel: device.localizedModel().toString(),
    systemName: device.systemName().toString(),
    systemVersion: device.systemVersion().toString(),
    identifierForVendor: device.identifierForVendor()?.UUIDString()?.toString() ?? "N/A",
    batteryLevel: device.batteryLevel(),
    batteryState: BATTERY_STATES[batteryStateRaw] ?? `Unknown (${batteryStateRaw})`,
    userInterfaceIdiom: UI_IDIOMS[idiomRaw] ?? `Unknown (${idiomRaw})`,
    isMultitaskingSupported: !!device.isMultitaskingSupported(),
  };
}

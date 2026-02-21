import ObjC from "frida-objc-bridge";

export interface PluginInfo {
  identifier: string;
  extensionPoint: string;
  displayName: string;
  version: string;
  path: string;
  uuid: string;
}

export function list(): PluginInfo[] {
  const workspace = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
  const allPlugins = workspace.installedPlugins();
  const mainBundleId = ObjC.classes.NSBundle.mainBundle()
    .bundleIdentifier()
    .toString();

  const result: PluginInfo[] = [];
  const count = allPlugins.count();

  for (let i = 0; i < count; i++) {
    const plugin = allPlugins.objectAtIndex_(i);
    const containingBundle = plugin.containingBundle();
    if (!containingBundle) continue;

    const containingBundleId = containingBundle.bundleIdentifier()?.toString();
    if (containingBundleId !== mainBundleId) continue;

    result.push({
      identifier: plugin.pluginIdentifier?.()?.toString() ?? "N/A",
      extensionPoint: plugin.protocol?.()?.toString() ?? "N/A",
      displayName: plugin.localizedName?.()?.toString() ?? "N/A",
      version: containingBundle
        .shortVersionString?.()
        ?.toString() ?? "N/A",
      path: plugin.bundleURL?.()?.path?.()?.toString() ?? "N/A",
      uuid: plugin.pluginUUID?.()?.UUIDString?.()?.toString() ?? "N/A",
    });
  }

  return result;
}

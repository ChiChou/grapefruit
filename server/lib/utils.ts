import path from "node:path";
import { promises as fsp } from "node:fs";

import frida from "frida";

export async function agent(name: string) {
  const scriptPath = path.join(
    import.meta.dirname,
    "..",
    "..",
    "agent",
    "dist",
    `${name}.js`,
  );

  return fsp.readFile(scriptPath, "utf8");
}

export async function ispawn(device: frida.Device, app: string): Promise<void> {
  const info = await device.querySystemParameters();
  if (info?.access === "jailed") {
    throw new Error(
      "jailed session to be supported in future, please submit a PR",
    );
  }

  const springboard = await device.attach("SpringBoard");
  const script = await springboard.createScript(await agent("springboard"));
  script.logHandler = (level, message) => {
    console.log(`Log from springboard agent [${level}]: ${message}`);
  };
  await script.load();
  await script.exports.open(app);
  await script.unload();
  await springboard.detach();
}

import cp from "node:child_process";

export const resolve = (relative: string) =>
  new URL(relative, import.meta.url).pathname;

export async function run(args: string[], opt: cp.SpawnOptions = {}) {
  const [bin, ...rest] = args;
  const extOpts: cp.SpawnOptions = Object.assign({ stdio: "inherit" }, opt);
  return new Promise<void>((resolve, reject) => {
    const proc = cp.spawn(bin, rest, extOpts);
    proc.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`patch process exited with code ${code}`));
      }
    });
  });
}

export async function patch(pkg: string, apply = false) {
  const info: { default: { version: string; main: string } } = await import(
    `../node_modules/${pkg}/package.json`,
    {
      with: { type: "json" },
    }
  );

  const { version, main } = info.default;
  const patchFile = resolve(`../patches/frida@${version}.patch`);
  const target = resolve(`../node_modules/${pkg}/${main}`);
  const args = ["patch", "-t", apply ? "-N" : "-R", "-i", patchFile, target];
  // ignore: Ignoring previously applied (or reversed) patch.
  return run(args).catch(() => {});
}

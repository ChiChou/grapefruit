import { $ } from "bun";

export const resolve = (relative: string) =>
  new URL(relative, import.meta.url).pathname;

export async function patch(pkg: string, apply = false) {
  const info = await import(`../node_modules/${pkg}/package.json`, {
    with: { type: "json" },
  });

  const { version, main } = info.default;
  const patchFile = resolve(`../patches/frida@${version}.patch`);
  const target = resolve(`../node_modules/${pkg}/${main}`);

  const direction = apply ? "-N" : "-R";

  // ignore: Ignoring previously applied (or reversed) patch.
  // Bun Shell throws on non-zero exit codes, so we catch to ignore errors
  await $`patch -t ${direction} -i ${patchFile} ${target}`.catch(() => {});
}

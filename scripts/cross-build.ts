import path from "node:path";
import cp from "node:child_process";

const bunTargets: Record<string, [string, string]> = {
  "bun-linux-x64": ["linux", "x64"],
  "bun-linux-arm64": ["linux", "arm64"],
  "bun-windows-x64": ["win32", "x64"],
  "bun-darwin-x64": ["darwin", "x64"],
  "bun-darwin-arm64": ["darwin", "arm64"],
  "bun-linux-x64-musl": ["linux", "x64"],
  "bun-linux-arm64-musl": ["linux", "arm64"],
};

const __dirname = import.meta.dirname;
const cwd = path.join(__dirname, "..", "node_modules", "frida");
console.warn("this script is experimental and not well tested");

function prebuild(cwd: string, platform?: string, arch?: string) {
  cp.spawnSync(
    process.execPath,
    [
      path.join(__dirname, "..", "node_modules", ".bin", "prebuild-install"),
      "-r",
      "napi",
      "--arch",
      arch || process.arch,
      "--platform",
      platform || process.platform,
    ],
    {
      cwd,
      stdio: "inherit",
    },
  );
}

for (const [target, [platform, arch]] of Object.entries(bunTargets)) {
  console.log("install prebuild for:", target);
  prebuild(cwd, platform, arch);

  // "build": "bun build index.ts --compile --outfile bin/portable"
  console.log("build bun binary for:", target);
  cp.spawnSync(
    process.execPath,
    [
      "build",
      path.join(__dirname, "..", "index.ts"),
      "--target",
      target,
      "--compile",
      "--outfile",
      path.join(__dirname, "..", "bin", target.replace("bun-", "portable-")),
    ],
    {
      stdio: "inherit",
    },
  );
}

// restore prebuild
prebuild(cwd);

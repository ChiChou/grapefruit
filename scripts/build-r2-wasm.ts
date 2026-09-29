import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  copyFile,
  cp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { need } from "./lib.ts";

const root = join(import.meta.dirname, "..");
const build = join(root, ".r2-wasm");
const source = join(build, "radare2");
const output = join(root, "radare2.wasm");
const marker = join(root, ".r2-wasm-id");
const revision = 1;

const r2 = {
  version: "6.1.2",
  commit: "fe5b09706cf30e4593821b1b2dc1bfe1b8c00735",
};

const plugins = [
  {
    name: "r2hermes",
    commit: "5faf591cb0ebe0cc702b5f708064c68f740997dd",
  },
  {
    name: "r2flutter",
    commit: "67935055e5a113ede14b4e410264fc8ee62e0c37",
  },
];

const id = [
  r2.version,
  `r${revision}`,
  ...plugins.map((p) => `${p.name}.${p.commit.slice(0, 7)}`),
].join("-");

function run(argv: string[], cwd = root, env = process.env) {
  const [command, ...args] = argv;
  const result = spawnSync(command, args, {
    cwd,
    env,
    stdio: "inherit",
    shell: false,
  });

  if (result.error) throw result.error;
  if (result.status) {
    throw new Error(`${argv.join(" ")} exited with code ${result.status}`);
  }
}

function read(argv: string[], cwd = root) {
  const [command, ...args] = argv;
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    shell: false,
  });

  if (result.error) throw result.error;
  if (result.status) {
    throw new Error(result.stderr.trim() || `${argv.join(" ")} failed`);
  }
  return result.stdout.trim();
}

async function checkPlugins() {
  for (const plugin of plugins) {
    const dir = join(root, "externals", "radare", plugin.name);
    if (!existsSync(join(dir, "r2plugin"))) {
      throw new Error(
        `${plugin.name} is missing; run git submodule update --init --recursive`,
      );
    }
    const actual = read([need("git"), "rev-parse", "HEAD"], dir);
    if (actual !== plugin.commit) {
      throw new Error(
        `${plugin.name} is at ${actual}; expected pinned commit ${plugin.commit}`,
      );
    }
  }
}

async function prepareSource() {
  await rm(source, { recursive: true, force: true });
  await mkdir(build, { recursive: true });
  run([need("git"), "init", source]);
  run(
    [need("git"), "remote", "add", "origin", "https://github.com/radareorg/radare2.git"],
    source,
  );
  run([need("git"), "fetch", "--depth", "1", "origin", r2.commit], source);
  run([need("git"), "checkout", "--detach", "FETCH_HEAD"], source);

  const actual = read([need("git"), "rev-parse", "HEAD"], source);
  if (actual !== r2.commit) {
    throw new Error(`radare2 ${r2.version} resolved to ${actual}; expected ${r2.commit}`);
  }

  const xps = join(source, "libr", "xps");
  for (const plugin of plugins) {
    const from = join(root, "externals", "radare", plugin.name);
    const to = join(xps, "p", plugin.name);
    await cp(from, to, {
      recursive: true,
      filter: (path) => basename(path) !== ".git" && basename(path) !== "build",
    });
  }

  const flutter = join(xps, "p", "r2flutter");
  run(
    [
      need("patch"),
      "-p1",
      "-i",
      join(root, "scripts", "patches", "r2flutter-r2-6.1.2.patch"),
    ],
    flutter,
  );

  const hermesCore = join(xps, "p", "r2hermes", "src", "r2", "core_hbc_one.c");
  const hermesSource = await readFile(hermesCore, "utf8");
  const pluginSymbol = `R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = (void *)&r_core_plugin_r2hermes,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};`;
  if (!hermesSource.includes(pluginSymbol)) {
    throw new Error("Unable to apply the r2hermes in-core symbol guard");
  }
  await writeFile(
    hermesCore,
    hermesSource.replace(
      pluginSymbol,
      `#ifndef R2_PLUGIN_INCORE\n${pluginSymbol}\n#endif`,
    ),
  );

  const hermesPlugin = join(xps, "p", "r2hermes", "src", "r2", "core_hbc.c");
  const pluginSource = await readFile(hermesPlugin, "utf8");
  const fixHbc = `r_core_cmd0 (core, "'(fix-hbc; ?e Fixing HBC footer hash...; r \`?vi $(pv4 @32)+20\`; wx \`ph sha1 $s-20 @0\` @ $s-20)");`;
  if (!pluginSource.includes(fixHbc)) {
    throw new Error("Unable to apply the r2hermes in-core initialization guard");
  }
  await writeFile(
    hermesPlugin,
    pluginSource.replace(fixHbc, `#ifndef R2_PLUGIN_INCORE\n\t${fixHbc}\n#endif`),
  );

  const wasiScript = join(source, "sys", "wasi-api.sh");
  const wasiSource = await readFile(wasiScript, "utf8");
  const allTools = "make -s -j${MAKE_JOBS} || exit 1";
  const radare2Only = [
    "make -s plugins.cfg libr/include/r_version.h || exit 1",
    "make -s -j${MAKE_JOBS} -C shlr sdbs || exit 1",
    "make -s -j${MAKE_JOBS} -C shlr/zip || exit 1",
    "make -s -j${MAKE_JOBS} -C libr/util || exit 1",
    "make -s -j${MAKE_JOBS} -C libr/socket || exit 1",
    "make -s -j${MAKE_JOBS} -C shlr || exit 1",
    "make -s -j${MAKE_JOBS} -C libr || exit 1",
    "make -s -C binr/radare2 || exit 1",
  ].join("\n");
  if (!wasiSource.includes(allTools)) {
    throw new Error("Unable to limit the radare2 WASI build targets");
  }
  await writeFile(wasiScript, wasiSource.replace(allTools, radare2Only));

  await writeFile(
    join(xps, "config.mk"),
    plugins.map((p) => `EXTERNAL_PLUGINS+=${p.name}`).join("\n") + "\n",
  );
  run([need("make"), "-C", "libr/xps"], source);
}

async function main() {
  if (process.platform === "win32") {
    throw new Error("The custom radare2 WASI build currently requires a Unix shell");
  }

  await checkPlugins();
  if (
    existsSync(output) &&
    existsSync(marker) &&
    (await readFile(marker, "utf8")).trim() === id
  ) {
    console.log(`[r2-wasm] ${id} already built`);
    return;
  }

  need("sh");
  need("make");
  need("patch");
  need("zip");
  await prepareSource();

  console.log(`[r2-wasm] building ${id}`);
  const wasiRoot = join(root, "wasi");
  const machine = read([need("uname"), "-m"]);
  const os = process.platform === "darwin" ? "macos" : "linux";
  const wasiSdk = join(wasiRoot, `wasi-sdk-29.0-${machine}-${os}`);
  const wasiSysroot = join(wasiRoot, "wasi-sysroot-29.0");
  run([need("sh"), "sys/wasi-api.sh"], source, {
    ...process.env,
    WASI_ROOT: wasiRoot,
    WASI_SDK: wasiSdk,
    WASI_SYSROOT: wasiSysroot,
    CC: `${join(wasiSdk, "bin", "clang")} --sysroot=${wasiSysroot} -DHAVE_PTHREAD=0 -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN -DHAVE_PTY=0 -DR2_NO_LONG_DOUBLE=1`,
  });

  const wasm = join(source, `radare2-${r2.version}-wasi-api`, "radare2.wasm");
  if (!existsSync(wasm)) throw new Error(`radare2 build did not produce ${wasm}`);
  await copyFile(wasm, output);
  await writeFile(marker, id + "\n");
  console.log(`[r2-wasm] wrote ${output}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

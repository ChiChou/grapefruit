import { parseArgs } from "node:util";

import { call, callKnown } from "./daemon/client.ts";
import { check } from "./daemon/rpc.ts";
import type { SessionInfo, Target } from "./daemon/protocol.ts";

const opts = {
  label: { type: "string", short: "L", default: "default" },
  project: { type: "string" },
  frida: { type: "string" },
  session: { type: "string", short: "s" },
  device: { type: "string", short: "d" },
  platform: { type: "string" },
  bundle: { type: "string", short: "b" },
  pid: { type: "string" },
  name: { type: "string", short: "n" },
  replace: { type: "boolean" },
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

type Values = Record<string, unknown>;

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

function platform(value: unknown): Target["platform"] {
  switch (value) {
    case "ios":
    case "fruity":
      return "fruity";
    case "android":
    case "droid":
      return "droid";
    default:
      fail("Error: --platform is required (ios|android|fruity|droid)");
  }
}

function target(values: Values): Target {
  const deviceId = values.device as string | undefined;
  if (!deviceId) fail("Error: --device is required");

  if (values.bundle) {
    return {
      deviceId,
      platform: platform(values.platform),
      mode: "app",
      bundle: values.bundle as string,
      name: values.name as string | undefined,
    };
  }

  if (values.pid) {
    return {
      deviceId,
      platform: platform(values.platform),
      mode: "daemon",
      pid: parseInt(values.pid as string, 10),
      name: values.name as string | undefined,
    };
  }

  fail("Error: --bundle or --pid is required");
}

function value(arg: string): unknown {
  if (!arg) return arg;
  if (!/^(?:true|false|null|-?\d|\[|\{|\")/.test(arg)) return arg;
  try {
    return JSON.parse(arg);
  } catch {
    return arg;
  }
}

function print(data: unknown, json = false) {
  if (data === undefined) return;
  if (json || typeof data !== "string") {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

function client(values: Values) {
  return {
    label: values.label as string | undefined,
    project: values.project as string | undefined,
    frida: values.frida as string | undefined,
  };
}

function splitRpc(spec: string): { ns: string; method: string } {
  const idx = spec.indexOf(".");
  if (idx <= 0 || idx === spec.length - 1) {
    fail("Error: RPC method must be namespace.method");
  }
  return { ns: spec.slice(0, idx), method: spec.slice(idx + 1) };
}

async function rpc(args: string[], values: Values) {
  const spec = args[0];
  if (!spec) fail("Error: rpc requires namespace.method");

  const { ns, method } = splitRpc(spec);
  check(ns, method);
  const result = await call(
    {
      method: "rpc",
      params: {
        session: values.session as string | undefined,
        target: values.session ? undefined : target(values),
        replace: values.replace === true,
        ns,
        method,
        args: args.slice(1).map(value),
      },
    },
    client(values),
  );
  print(result, values.json === true);
}

async function session(args: string[], values: Values) {
  const sub = args[0] ?? "ls";

  switch (sub) {
    case "ls":
    case "list": {
      const result = await call<SessionInfo[]>(
        { method: "session.list", params: {} },
        client(values),
      );
      if (values.json) {
        print(result, true);
      } else {
        for (const s of result) {
          const target = s.mode === "app" ? s.bundle : `${s.name || "pid"}:${s.pid}`;
          console.log(`${s.id} ${s.platform} ${s.mode} ${s.deviceId} ${target} refs=${s.refs}`);
        }
      }
      break;
    }

    case "open": {
      const result = await call(
        {
          method: "session.open",
          params: { target: target(values), replace: values.replace === true },
        },
        client(values),
      );
      print(result, values.json === true);
      break;
    }

    case "close": {
      const id = args[1] ?? (values.session as string | undefined);
      if (!id) fail("Error: session close requires <id>");
      print(
        await call({ method: "session.close", params: { id } }, client(values)),
        values.json === true,
      );
      break;
    }

    case "gc":
      print(await call({ method: "session.gc", params: {} }, client(values)), values.json === true);
      break;

    default:
      fail(`Unknown session subcommand: ${sub}`);
  }
}

function help() {
  console.log(`
IGF CLI

Usage:
  igf rpc [target] <namespace.method> [args...]
  igf session ls
  igf session open [target]
  igf session close <id>
  igf daemon stop
  igf setup [--global]

Target:
  --device <id> --platform <ios|android> --bundle <id>
  --device <id> --platform <ios|android> --pid <pid> [--name <name>]
  --session <id>

Daemon:
  -L, --label <name>     tmux-style daemon label (default: default)
  --project <path>       data directory passed to auto-started daemon
  --replace              replace an active iOS app session when needed
  --json                 force JSON output

RPC scope:
  Platform inspection and managed captures. Use Frida directly for code
  execution, memory, threads, module/symbol enumeration, and process metadata.
`);
}

export async function run(argv: string[]) {
  const parsed = parseArgs({
    args: argv,
    options: opts,
    allowPositionals: true,
    strict: false,
  });
  const [cmd, ...args] = parsed.positionals;
  const values = parsed.values as Values;

  if (!cmd || (values.help && cmd !== "setup")) {
    help();
    process.exit(cmd ? 0 : 1);
  }

  switch (cmd) {
    case "daemon": {
      if (args[0] === "stop") {
        print(
          await callKnown({ method: "shutdown", params: {} }, client(values)),
          values.json === true,
        );
      } else {
        const { run: daemon } = await import("./daemon/server.ts");
        await daemon((values.label as string | undefined) ?? "default");
      }
      break;
    }
    case "rpc":
      await rpc(args, values);
      break;
    case "session":
      await session(args, values);
      break;
    case "setup": {
      const { run: setup } = await import("./setup.ts");
      await setup(argv.slice(argv.indexOf(cmd) + 1));
      break;
    }
    default:
      fail(`Unknown command: ${cmd}`);
  }
}

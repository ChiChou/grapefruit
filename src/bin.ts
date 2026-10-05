import { parseArgs } from "node:util";
import { schema } from "./lib/cli.ts";

const ctlCommands = ["daemon", "rpc", "session", "setup"];

function command(argv: string[]): string | undefined {
  const valueOpts = new Set([
    "-L",
    "--label",
    "-s",
    "--session",
    "-d",
    "--device",
    "--platform",
    "-b",
    "--bundle",
    "--pid",
    "-n",
    "--name",
    "--frida",
    "--host",
    "--port",
    "--project",
  ]);

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") return argv[i + 1];
    if (!arg.startsWith("-")) return arg;

    const name = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
    if (valueOpts.has(name) && !arg.includes("=")) i++;
  }
}

const args = parseArgs(schema);

if (args.values.help && !args.positionals[0]) {
  console.log(`
IGF - Grapefruit Dynamic Instrumentation Server

Usage:
  igf [options]           Start the server (default)
  igf <command> [args]    Run CLI command

Server Options:
  --frida <16 | 17>      Specify Frida version to use (default: 17)
  --host <host>          Host to bind the server (default: 127.0.0.1)
  --port <port>          Port to bind the server (default: 31337)
  --project <path>       Project directory for data/cache/logs (default: .igf in cwd)
                         Can also be set via PROJECT_DIR environment variable
  --no-open              Do not open browser on startup
  --help, -h             Show this help message

CLI Commands:
  rpc                    Run platform inspection or managed capture RPC
  session                Manage daemon-owned instrumentation sessions
  setup                  Install Claude Code skills (/igf, /mastg)

Run 'igf <command> --help' for command details.
`);
  process.exit(0);
}

const firstArg = command(process.argv.slice(2));

if (firstArg && ctlCommands.includes(firstArg)) {
  import("./ctl.ts").then((m) => m.run(process.argv.slice(2)));
} else {
  import("./index.ts");
}

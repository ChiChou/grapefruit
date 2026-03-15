import { parseArgs } from "node:util";
import { schema } from "./lib/cli.ts";

const cliCommands = ["version", "device", "log", "history", "agent"];

const args = parseArgs(schema);

if (args.values.help) {
  console.log(`
IGF - Grapefruit Dynamic Instrumentation Server

Usage:
  igf [options]           Start the server (default)
  igf <command> [args]    Run CLI command

Server Options:
  --frida <16 | 17>      Specify Frida version to use (default: 17)
  --host <host>          Host to bind the server (default: localhost)
  --port <port>          Port to bind the server (default: 31337)
  --project <path>       Project directory for data/cache/logs (default: .igf in cwd)
                         Can also be set via PROJECT_DIR environment variable
  --help, -h             Show this help message

CLI Commands:
  version                Show Frida & IGF versions
  device <subcommand>    Device management (list|apps|ps|info|kill)
  log <subcommand>       Log management (hooks|crypto|syslog|agent|clear)
  history <subcommand>   Query history data (http|nsurl|jni|flutter|xpc|privacy|hermes)
  agent <namespace>      Agent RPC commands

Run 'igf <command> --help' for command details.
`);
  process.exit(0);
}

const firstArg = args.positionals[0];

if (firstArg && cliCommands.includes(firstArg)) {
  import("./cli/commands.ts").then((m) => m.runCLI(process.argv.slice(2)));
} else {
  import("./index.ts");
}

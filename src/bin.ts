import { parseArgs } from "node:util";
import { schema } from "./lib/cli.ts";

const args = parseArgs(schema);
if (args.values.help) {
  console.log(`
Usage: igf [options]

Options:
  --frida <16 | 17>  Specify Frida version to use (default: 17)
  --host <host>      Host to bind the server (default: localhost)
  --port <port>      Port to bind the server (default: 31337)
  --project <path>   Project directory for data/cache/logs (default: .igf in cwd)
                     Can also be set via PROJECT_DIR environment variable
  --help, -h         Show this help message
  `);
  process.exit(0);
}

import("./index.ts");

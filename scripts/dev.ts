import { spawn } from "node:child_process";
import { once } from "node:events";
import { join } from "node:path";

import { npm, tool } from "./lib.ts";

const root = join(import.meta.dirname, "..");
const agent = join(root, "agent");
const gui = join(root, "gui");

const mode = process.argv[2];
process.env.NODE_ENV = "development";
const env = { ...process.env };

type Pane = {
  name: string;
  cwd: string;
  cmd: string[];
};

const serverPanes: Pane[] = [
  { name: "server", cwd: root, cmd: npm("run", "dev") },
  { name: "gui", cwd: gui, cmd: npm("run", "dev") },
];

const agentPanes: Pane[] = [
  {
    name: "fruity",
    cwd: agent,
    cmd: npm("run", "build:fruity", "--", "--watch"),
  },
  {
    name: "droid",
    cwd: agent,
    cmd: npm("run", "build:droid", "--", "--watch"),
  },
  {
    name: "transport",
    cwd: agent,
    cmd: npm("run", "build:transport", "--", "--watch"),
  },
];

const panes = mode === "both" ? serverPanes : [...agentPanes, ...serverPanes];

function launch(command: string, args: string[], cwd = root) {
  const proc = spawn(command, args, { cwd, env, stdio: "inherit" });
  proc.on("error", (error) => {
    console.error(error);
    process.exitCode = 1;
  });
  return proc;
}

function tmux(panes: Pane[]) {
  const command = tool("tmux");
  if (!command) return false;

  const args = [
    "new-session",
    "-c",
    panes[0].cwd,
    panes[0].cmd.join(" "),
  ];
  for (let i = 1; i < panes.length; i++) {
    const pane = panes[i];
    if (mode === "all" && pane.name === "server") {
      args.push(";", "select-layout", "even-horizontal", ";", "new-window");
    } else {
      args.push(";", "split-window", "-h");
    }
    args.push("-c", pane.cwd, pane.cmd.join(" "));
  }
  args.push(";", "select-layout", "even-horizontal", ";", "select-pane", "-t", "0");
  launch(command, args);
  return true;
}

function terminal(panes: Pane[]) {
  const command = tool("wt.exe") ?? tool("wt");
  if (!command) return false;

  const [first, ...rest] = panes;
  const args = ["-d", first.cwd, ...first.cmd];
  for (const { cwd, cmd } of rest) {
    args.push(";", "new-tab", "-d", cwd, ...cmd);
  }
  spawn(command, args, { env, detached: true, stdio: "ignore" }).unref();
  return true;
}

async function local(panes: Pane[]) {
  console.log("No terminal multiplexer found; running dev processes here.");
  const procs = panes.map((pane) => {
    console.log(`[${pane.name}] ${pane.cmd.join(" ")}`);
    return { pane, proc: launch(pane.cmd[0], pane.cmd.slice(1), pane.cwd) };
  });

  const stop = () => {
    for (const { proc } of procs) proc.kill();
  };

  for (const sig of ["SIGINT", "SIGTERM"] as const) {
    process.on(sig, () => {
      stop();
      process.exit(sig === "SIGINT" ? 130 : 143);
    });
  }

  const first = await Promise.race(
    procs.map(async ({ pane, proc }) => {
      const [code] = (await once(proc, "exit")) as [number | null];
      return { pane, code: code ?? 1 };
    }),
  );

  stop();
  process.exitCode = first.code;
  console.error(`[${first.pane.name}] exited with code ${first.code}`);
}

if (process.platform === "win32") {
  if (!terminal(panes)) await local(panes);
} else if (!tmux(panes)) {
  await local(panes);
}

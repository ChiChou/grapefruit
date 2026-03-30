import cp from "node:child_process";
import os from "node:os";
import path from "node:path";

const isWindows = os.platform() === "win32";
const root = path.join(import.meta.dirname, "..");
const runner = process.env.npm_execpath || "bun";

const panes = [
  { cwd: path.join(root, "agent"), cmd: `${runner} run build:fruity -- --watch` },
  { cwd: path.join(root, "agent"), cmd: `${runner} run build:droid -- --watch` },
  { cwd: path.join(root, "gui"), cmd: `${runner} run dev` },
  { cwd: root, cmd: `${runner} run dev` },
];

function tmux() {
  const [fruity, droid, gui, server] = panes;
  const script = [
    `new-session -c ${server.cwd} ${server.cmd}`,
    `split-window -v -l 40% -c ${gui.cwd} ${gui.cmd}`,
    `select-pane -t 0`,
    `split-window -h -l 30% -c ${fruity.cwd} ${fruity.cmd}`,
    `split-window -v -c ${droid.cwd} ${droid.cmd}`,
    `select-pane -t 0`,
  ].join(" \\; ");
  cp.execSync(`tmux ${script}`, { stdio: "inherit" });
}

function wt() {
  const [first, ...rest] = panes;
  const argv = ["-d", first.cwd, ...first.cmd.split(" ")];
  for (const { cwd, cmd } of rest) {
    argv.push(";", "new-tab", "-d", cwd, ...cmd.split(" "));
  }
  cp.spawn("wt", argv);
  process.exit();
}

process.env.NODE_ENV = "development";

if (isWindows) {
  wt();
} else {
  tmux();
}

import cp from "node:child_process";
import os from "node:os";
import path from "node:path";

const isWindows = os.platform() === "win32";
const root = path.join(import.meta.dirname, "..");
const runner = process.env.npm_execpath || "bun";

const agent = path.join(root, "agent");
const gui = path.join(root, "gui");

// Tab 1 — agent watches: ┌─────┬─────┬─────┐
//                         │fruit│droid│trans│
//                         └─────┴─────┴─────┘
// Tab 2 — dev servers:    ┌───────┬─────────┐
//                         │server │  gui     │
//                         └───────┴─────────┘
function tmux() {
  const script = [
    `new-session -c ${agent} ${runner} run build:fruity -- --watch`,
    `split-window -h -c ${agent} ${runner} run build:droid -- --watch`,
    `split-window -h -c ${agent} ${runner} run build:transport -- --watch`,
    `select-layout even-horizontal`,
    `new-window -c ${root} ${runner} run dev`,
    `split-window -h -c ${gui} ${runner} run dev`,
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

import { join } from "node:path";
import { $ } from "bun";

const root = join(import.meta.dirname, "..");
const agent = join(root, "agent");
const gui = join(root, "gui");

const mode = process.argv[2]; // "all" or "both"

// ┌───────┬─────────┐
// │server │  gui     │
// └───────┴─────────┘
async function both() {
  await $`tmux \
    new-session  -c ${root}  bun run dev \; \
    split-window -h -c ${gui} bun run dev \; \
    select-pane -t 0`;
}

// Tab 1: ┌─────┬─────┬─────┐
//         │fruit│droid│trans│
//         └─────┴─────┴─────┘
// Tab 2: ┌───────┬─────────┐
//         │server │  gui     │
//         └───────┴─────────┘
async function all() {
  await $`tmux \
    new-session  -c ${agent} bun run build:fruity -- --watch \; \
    split-window -h -c ${agent} bun run build:droid -- --watch \; \
    split-window -h -c ${agent} bun run build:transport -- --watch \; \
    select-layout even-horizontal \; \
    new-window   -c ${root}  bun run dev \; \
    split-window -h -c ${gui} bun run dev \; \
    select-pane -t 0`;
}

function wt() {
  const panes = [
    { cwd: agent, cmd: "bun run build:fruity -- --watch" },
    { cwd: agent, cmd: "bun run build:droid -- --watch" },
    { cwd: agent, cmd: "bun run build:transport -- --watch" },
    { cwd: root, cmd: "bun run dev" },
    { cwd: gui, cmd: "bun run dev" },
  ];
  const [first, ...rest] = panes;
  const argv = ["-d", first.cwd, ...first.cmd.split(" ")];
  for (const { cwd, cmd } of rest) {
    argv.push(";", "new-tab", "-d", cwd, ...cmd.split(" "));
  }
  Bun.spawn(["wt", ...argv]).unref();
}

process.env.NODE_ENV = "development";

if (process.platform === "win32") {
  wt();
} else if (mode === "both") {
  await both();
} else {
  await all();
}

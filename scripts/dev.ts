import cp from "node:child_process";
import os from "node:os";
import path from "node:path";

const isWindows = os.platform() === "win32";
const npm = isWindows ? "npm.cmd" : "npm";
const args = ["run", "dev"];

const subprojects = ["agent", "server", "gui"] as const;
const subdirs = subprojects.map((name) =>
  path.join(import.meta.dirname, "..", name),
);

function tmux() {
  const argv = ["new-session"];
  for (const cwd of subdirs) {
    argv.push("-c", cwd, "npm");
    argv.push(...args);
    argv.push(";", "split-window", "-h");
  }
  // last split-window
  argv.pop();
  argv.pop();
  // C-a space
  argv.push("next-layout");
  cp.spawnSync("tmux", argv, { stdio: "inherit" });
}

function wt() {
  const argv: string[] = [];
  for (const cwd of subdirs) {
    argv.push("-d", cwd, npm);
    argv.push(...args);
    argv.push(";", "new-tab");
  }
  argv.push("cmd", "/c", "echo OK");
  cp.spawn("wt", argv);
  process.exit(); // detach
}

async function main() {
  if (isWindows) {
    wt();
  } else {
    tmux();
  }
}

main();

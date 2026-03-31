import { execFile } from "node:child_process";

const commands: Record<string, string[]> = {
  darwin: ["open"],
  win32: ["cmd", "/c", "start", ""],
  linux: ["xdg-open"],
};

export default function open(url: string) {
  const entry = commands[process.platform];
  if (!entry) return;
  const [cmd, ...args] = entry;
  const cp = execFile(cmd, [...args, url]);
  cp.stdin?.destroy();
  cp.stdout?.destroy();
  cp.stderr?.destroy();
  cp.unref();
}

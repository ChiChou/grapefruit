import fs from "node:fs/promises";
import path from "node:path";

import env from "./env.ts";

export class Writer {
  private syslog: fs.FileHandle;
  private agentLog: fs.FileHandle;

  private constructor(syslog: fs.FileHandle, agentLog: fs.FileHandle) {
    this.syslog = syslog;
    this.agentLog = agentLog;
  }

  static async open(deviceId: string, identifier: string): Promise<Writer> {
    const logsDir = path.join(
      env.workdir,
      "data",
      "logs",
      deviceId,
      identifier,
    );
    await fs.mkdir(logsDir, { recursive: true });
    const [syslog, agentLog] = await Promise.all([
      fs.open(path.join(logsDir, "syslog.log"), "a"),
      fs.open(path.join(logsDir, "agent.log"), "a"),
    ]);
    return new Writer(syslog, agentLog);
  }

  appendSyslog(text: string) {
    this.syslog.appendFile(text + "\n").catch(() => {});
  }

  appendAgentLog(level: string, text: string) {
    this.agentLog.appendFile(`[${level}] ${text}\n`).catch(() => {});
  }

  async empty(type: "syslog" | "agent") {
    const handle = type === "syslog" ? this.syslog : this.agentLog;
    await handle.truncate(0);
  }

  async close() {
    await Promise.all([this.syslog.close(), this.agentLog.close()]).catch(
      () => {},
    );
  }
}

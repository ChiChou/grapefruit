import fs from "node:fs/promises";
import path from "node:path";

import paths from "./paths.ts";

export class LogWriter {
  private syslog: fs.FileHandle;
  private agentLog: fs.FileHandle;

  private constructor(syslog: fs.FileHandle, agentLog: fs.FileHandle) {
    this.syslog = syslog;
    this.agentLog = agentLog;
  }

  static async open(deviceId: string, identifier: string): Promise<LogWriter> {
    const logsDir = path.join(paths.data, "logs", deviceId, identifier);
    await fs.mkdir(logsDir, { recursive: true });
    const [syslog, agentLog] = await Promise.all([
      fs.open(path.join(logsDir, "syslog.log"), "a"),
      fs.open(path.join(logsDir, "agent.log"), "a"),
    ]);
    return new LogWriter(syslog, agentLog);
  }

  appendSyslog(text: string) {
    this.syslog.appendFile(text + "\n");
  }

  appendAgentLog(level: string, text: string) {
    this.agentLog.appendFile(`[${level}] ${text}\n`);
  }

  async close() {
    await Promise.all([this.syslog.close(), this.agentLog.close()]).catch(
      () => {},
    );
  }
}

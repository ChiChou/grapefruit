import { mkdir } from "node:fs/promises";
import { execSync } from "node:child_process";

await mkdir("./agent/dist", { recursive: true });

execSync(`bun i`, { cwd: "./agent", stdio: "inherit" });
execSync(`bun i`, { cwd: "./gui", stdio: "inherit" });

import cp from "node:child_process";

import { allBuildScripts, root } from "./utils.ts";

async function run() {
  for await (const [name, cmd] of allBuildScripts()) {
    console.log("run", name);
    cp.spawn(`npx ${cmd} -c`, {
      stdio: "inherit",
      shell: true,
      cwd: root,
    });
  }
}

run();

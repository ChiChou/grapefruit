import cp from "node:child_process";

import { allBuildScripts, root } from "./utils.ts";

async function run() {
  for await (const [name, cmd] of allBuildScripts()) {
    console.log(name.replace("build:", "watch:"));
    cp.spawn(`npx ${cmd} -w`, {
      stdio: "inherit",
      shell: true,
      cwd: root,
    });
  }
}

run();

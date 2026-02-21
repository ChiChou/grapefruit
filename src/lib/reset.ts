import fs from "node:fs";
import { styleText } from "node:util";
import envPaths from "env-paths";

const paths = envPaths("ist.codecolor.grapefruit", { suffix: "" });

export function reset(dryRun: boolean) {
  const dirs = [paths.data, paths.cache, paths.config, paths.log];

  console.log("This command is going to reset your data, use it when you want to reset the settings or uninstall.");
  console.log(styleText("dim", "It's not going to remove your browser data related to Web UI."));

  if (dryRun) {
    console.log(styleText("yellow", "Dry run — the following directories would be removed:"));
  } else {
    console.log(styleText("red", "Resetting igf — removing all data:"));
  }

  console.log();
  let found = false;
  for (const dir of dirs) {
    if (fs.existsSync(dir)) {
      found = true;
      if (dryRun) {
        console.log(`  ${styleText("yellow", "would remove")}  ${dir}`);
      } else {
        console.log(`  ${styleText("red", "removing")}      ${dir}`);
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
  }

  console.log();
  if (!found) {
    console.log(styleText("green", "Nothing to clean up — already clean."));
  } else if (dryRun) {
    console.log(styleText("dim", "No files were deleted. Run without --dry-run to remove them."));
  } else {
    console.log(styleText("green", "Done."));
  }

  process.exit(0);
}

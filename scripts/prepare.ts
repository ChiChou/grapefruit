import { $ } from "bun";

await Bun.write("./agent/dist/.create", "");

await $`bun i`.cwd("agent");
await $`bun i`.cwd("gui");

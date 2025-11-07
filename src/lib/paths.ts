import fs from "node:fs";
import envPaths from "env-paths";

const paths = envPaths("ist.codecolor.grapefruit", { suffix: "" });

const keys = new Set(Object.keys(paths));
const proxy = new Proxy(paths, {
  get(target, prop, receiver) {
    const original = Reflect.get(target, prop, receiver);
    if (
      typeof prop === "string" &&
      keys.has(prop) &&
      !fs.existsSync(original)
    ) {
      fs.mkdirSync(original, { recursive: true });
    }

    return original;
  },
});

export default proxy;

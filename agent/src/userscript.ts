const bridges = ["objc", "swift", "java"] as const;

function loadBridge(name: (typeof bridges)[number]) {
  let bridge: unknown;

  send({ type: "frida:load-bridge", name });
  recv("frida:bridge-loaded", (message) => {
    bridge = Script.evaluate(
      `/frida/bridges/${message.filename}`,
      "(function () { " +
        [
          message.source,
          `Object.defineProperty(globalThis, '${name}', { value: bridge });`,
          `return bridge;`,
        ].join("\n") +
        " })();",
    );
  }).wait();

  return bridge;
}

for (const name of bridges) {
  Object.defineProperty(globalThis, name, {
    enumerable: true,
    configurable: true,
    get: () => loadBridge(name),
  });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
rpc.exports.evaluate = (source: string, name = "userscript"): any =>
  Script.evaluate(name, source);

const bridges = ["ObjC", "Swift", "Java"] as const;

interface PingbackMessage {
  filename: string;
  source: string;
}

function loadBridge(name: (typeof bridges)[number]) {
  let bridge: unknown;

  send({ subject: "frida:load-bridge", name });
  recv("frida:bridge-loaded", (message: PingbackMessage) => {
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

function init() {
  for (const name of bridges) {
    Object.defineProperty(globalThis, name, {
      enumerable: true,
      configurable: true,
      get: () => loadBridge(name),
    });
  }
}

let initialized = false;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function evaluate(source: string, name = "userscript"): any {
  if (!initialized) {
    init();
    initialized = true;
  }

  return Script.evaluate(name, source);
}

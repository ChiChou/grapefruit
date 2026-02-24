export type RNArch = "legacy" | "bridgeless";

export interface RNInstance {
  className: string;
  arch: RNArch;
  handle: string;
}

export function sendHermesByteCode(url: string, bytes: ArrayBuffer) {
  send({ subject: "hermes", url, size: bytes.byteLength }, bytes);
}

export function hookHermesEvaluate(label: string): InvocationListener[] {
  const listeners: InvocationListener[] = [];
  const resolver = new ApiResolver("module");
  const matches = resolver.enumerateMatches(
    "exports:*hermes*!*evaluateJavaScript*",
  );
  for (const m of matches) {
    listeners.push(
      Interceptor.attach(m.address, {
        onEnter() {
          console.log(`[${label}][Hermes] evaluateJavaScript called`);
        },
      }),
    );
  }
  return listeners;
}

export function createCallbackContext() {
  const pending = new Map<string, (result: string) => void>();
  let nextId = Math.floor(Math.random() * 100000);

  function parseCallback(message: string): boolean {
    if (!message.startsWith("frida-callback:")) return false;
    const firstColon = message.indexOf(":");
    const secondColon = message.indexOf(":", firstColon + 1);
    const id = message.substring(firstColon + 1, secondColon);
    const result = message.substring(secondColon + 1);
    const cb = pending.get(id);
    if (cb) {
      pending.delete(id);
      cb(result);
    }
    return true;
  }

  function prepare(script: string): { id: string; path: string } {
    const id = String(++nextId);
    const path = Process.getTmpDir() + `/rn-frida-${id}.js`;
    const wrapped = `
try {
  var r = (function() { return ${script} })();
  alert('frida-callback:${id}:' + JSON.stringify(r));
} catch (e) {
  alert('frida-callback:${id}:' + JSON.stringify({ error: e.message }));
}
`;
    const f = new File(path, "w");
    f.write(wrapped);
    f.close();
    return { id, path };
  }

  function register(id: string, resolve: (result: string) => void) {
    pending.set(id, resolve);
  }

  function cleanup(id: string, path: string) {
    pending.delete(id);
    // unlink(path);
  }

  return { parseCallback, prepare, register, cleanup };
}

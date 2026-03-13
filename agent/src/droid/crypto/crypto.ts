import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook } from "@/common/hooks/java.js";
import { byteArrayToBuffer } from "@/droid/lib/jbytes.js";

const CIPHER_MODES: Record<number, string> = {
  1: "ENCRYPT",
  2: "DECRYPT",
  3: "WRAP",
  4: "UNWRAP",
};

function javaBt(): string[] {
  const frames = Java.use("java.lang.Thread").currentThread().getStackTrace();
  const result: string[] = [];
  for (let i = 2; i < Math.min(frames.length, 20); i++) {
    result.push(frames[i].toString());
  }
  return result;
}

function toBuffer(byteArr: Java.Wrapper | null): ArrayBuffer | null {
  if (!byteArr) return null;
  const result = byteArrayToBuffer(byteArr);
  return result ? result.data : null;
}

export function cipher() {
  const hooks: InvocationListener[] = [];

  Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");

    // getInstance(String)
    hooks.push(hook(
      Cipher.getInstance.overload("java.lang.String"),
      (original, self, args) => {
        const [transformation] = args;
        const result = original.call(self, transformation);
        send({
          subject: "crypto",
          category: "cipher",
          symbol: "Cipher.getInstance",
          dir: "enter",
          line: `Cipher.getInstance("${transformation}")`,
          backtrace: javaBt(),
          extra: { transformation: String(transformation) },
        } satisfies BaseMessage);
        return result;
      },
    ));

    // getInstance(String, String)
    hooks.push(hook(
      Cipher.getInstance.overload("java.lang.String", "java.lang.String"),
      (original, self, args) => {
        const [transformation, provider] = args;
        const result = original.call(self, transformation, provider);
        send({
          subject: "crypto",
          category: "cipher",
          symbol: "Cipher.getInstance",
          dir: "enter",
          line: `Cipher.getInstance("${transformation}", "${provider}")`,
          backtrace: javaBt(),
          extra: {
            transformation: String(transformation),
            provider: String(provider),
          },
        } satisfies BaseMessage);
        return result;
      },
    ));

    // init(int, Key)
    hooks.push(hook(
      Cipher.init.overload("int", "java.security.Key"),
      (original, self, args) => {
        const [mode, key] = args;
        const op = CIPHER_MODES[mode as number] || String(mode);
        const algo = self.getAlgorithm();
        send({
          subject: "crypto",
          category: "cipher",
          symbol: "Cipher.init",
          dir: "enter",
          line: `Cipher.init(${op}, ${(key as Java.Wrapper).$className}) [${algo}]`,
          backtrace: javaBt(),
          extra: { op, algo },
        } satisfies BaseMessage);
        original.call(self, mode, key);
      },
    ));

    // init(int, Key, AlgorithmParameterSpec)
    hooks.push(hook(
      Cipher.init.overload(
        "int",
        "java.security.Key",
        "java.security.spec.AlgorithmParameterSpec",
      ),
      (original, self, args) => {
        const [mode, key, spec] = args;
        const op = CIPHER_MODES[mode as number] || String(mode);
        const algo = self.getAlgorithm();
        send({
          subject: "crypto",
          category: "cipher",
          symbol: "Cipher.init",
          dir: "enter",
          line: `Cipher.init(${op}, ${(key as Java.Wrapper).$className}, ${(spec as Java.Wrapper).$className}) [${algo}]`,
          backtrace: javaBt(),
          extra: { op, algo },
        } satisfies BaseMessage);
        original.call(self, mode, key, spec);
      },
    ));

    // doFinal()
    hooks.push(hook(
      Cipher.doFinal.overload(),
      (original, self) => {
        const algo = self.getAlgorithm();
        send({
          subject: "crypto",
          category: "cipher",
          symbol: "Cipher.doFinal",
          dir: "enter",
          line: `Cipher.doFinal() [${algo}]`,
          backtrace: javaBt(),
          extra: { algo },
        } satisfies BaseMessage);
        const result = original.call(self);
        const buf = toBuffer(result as Java.Wrapper);
        if (buf) {
          send(
            {
              subject: "crypto",
              category: "cipher",
              symbol: "Cipher.doFinal",
              dir: "leave",
              line: `Cipher.doFinal() → [${buf.byteLength}B] [${algo}]`,
              extra: { algo, detailType: "output", len: buf.byteLength },
            } satisfies BaseMessage,
            buf,
          );
        }
        return result;
      },
    ));

    // doFinal(byte[])
    hooks.push(hook(
      Cipher.doFinal.overload("[B"),
      (original, self, args) => {
        const [input] = args;
        const algo = self.getAlgorithm();
        const inBuf = toBuffer(input as Java.Wrapper);
        if (inBuf) {
          send(
            {
              subject: "crypto",
              category: "cipher",
              symbol: "Cipher.doFinal",
              dir: "enter",
              line: `Cipher.doFinal(input[${inBuf.byteLength}B]) [${algo}]`,
              backtrace: javaBt(),
              extra: { algo, detailType: "input", len: inBuf.byteLength },
            } satisfies BaseMessage,
            inBuf,
          );
        }
        const result = original.call(self, input);
        const outBuf = toBuffer(result as Java.Wrapper);
        if (outBuf) {
          send(
            {
              subject: "crypto",
              category: "cipher",
              symbol: "Cipher.doFinal",
              dir: "leave",
              line: `Cipher.doFinal() → [${outBuf.byteLength}B] [${algo}]`,
              extra: { algo, detailType: "output", len: outBuf.byteLength },
            } satisfies BaseMessage,
            outBuf,
          );
        }
        return result;
      },
    ));

    // update(byte[])
    hooks.push(hook(
      Cipher.update.overload("[B"),
      (original, self, args) => {
        const [input] = args;
        const algo = self.getAlgorithm();
        const inBuf = toBuffer(input as Java.Wrapper);
        if (inBuf) {
          send(
            {
              subject: "crypto",
              category: "cipher",
              symbol: "Cipher.update",
              dir: "enter",
              line: `Cipher.update(input[${inBuf.byteLength}B]) [${algo}]`,
              backtrace: javaBt(),
              extra: { algo, detailType: "input", len: inBuf.byteLength },
            } satisfies BaseMessage,
            inBuf,
          );
        }
        const result = original.call(self, input);
        const outBuf = toBuffer(result as Java.Wrapper);
        if (outBuf) {
          send(
            {
              subject: "crypto",
              category: "cipher",
              symbol: "Cipher.update",
              dir: "leave",
              line: `Cipher.update() → [${outBuf.byteLength}B] [${algo}]`,
              extra: { algo, detailType: "output", len: outBuf.byteLength },
            } satisfies BaseMessage,
            outBuf,
          );
        }
        return result;
      },
    ));
  });

  return hooks;
}

export function pbkdf() {
  const hooks: InvocationListener[] = [];

  Java.perform(() => {
    const PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
    const StringCls = Java.use("java.lang.String");

    const toStr = (arr: Java.Wrapper | null) =>
      arr === null ? "(null)" : StringCls.$new(arr).toString();

    // PBEKeySpec(char[])
    hooks.push(hook(
      PBEKeySpec.$init.overload("[C"),
      (original, self, args) => {
        const [pass] = args;
        const password = toStr(pass as Java.Wrapper);
        send({
          subject: "crypto",
          category: "pbkdf",
          symbol: "PBEKeySpec",
          dir: "enter",
          line: `PBEKeySpec(pass="${password}")`,
          backtrace: javaBt(),
          extra: { password },
        } satisfies BaseMessage);
        original.call(self, pass);
      },
    ));

    // PBEKeySpec(char[], byte[], int)
    hooks.push(hook(
      PBEKeySpec.$init.overload("[C", "[B", "int"),
      (original, self, args) => {
        const [pass, salt, iter] = args;
        const password = toStr(pass as Java.Wrapper);
        const saltBuf = toBuffer(salt as Java.Wrapper);
        send(
          {
            subject: "crypto",
            category: "pbkdf",
            symbol: "PBEKeySpec",
            dir: "enter",
            line: `PBEKeySpec(pass="${password}", salt[${(salt as Java.Wrapper)?.length ?? 0}B], iter=${iter})`,
            backtrace: javaBt(),
            extra: {
              password,
              iterations: iter,
              detailType: "salt",
              len: (salt as Java.Wrapper)?.length ?? 0,
            },
          } satisfies BaseMessage,
          saltBuf,
        );
        original.call(self, pass, salt, iter);
      },
    ));

    // PBEKeySpec(char[], byte[], int, int)
    hooks.push(hook(
      PBEKeySpec.$init.overload("[C", "[B", "int", "int"),
      (original, self, args) => {
        const [pass, salt, iter, keyLen] = args;
        const password = toStr(pass as Java.Wrapper);
        const saltBuf = toBuffer(salt as Java.Wrapper);
        send(
          {
            subject: "crypto",
            category: "pbkdf",
            symbol: "PBEKeySpec",
            dir: "enter",
            line: `PBEKeySpec(pass="${password}", salt[${(salt as Java.Wrapper)?.length ?? 0}B], iter=${iter}, keyLen=${keyLen})`,
            backtrace: javaBt(),
            extra: {
              password,
              iterations: iter,
              keyLength: keyLen,
              detailType: "salt",
              len: (salt as Java.Wrapper)?.length ?? 0,
            },
          } satisfies BaseMessage,
          saltBuf,
        );
        original.call(self, pass, salt, iter, keyLen);
      },
    ));
  });

  return hooks;
}

export function keygen() {
  const hooks: InvocationListener[] = [];

  Java.perform(() => {
    const Builder = Java.use(
      "android.security.keystore.KeyGenParameterSpec$Builder",
    );

    const boolMethods = [
      "setUserAuthenticationRequired",
      "setRandomizedEncryptionRequired",
      "setInvalidatedByBiometricEnrollment",
      "setUnlockedDeviceRequired",
      "setUserConfirmationRequired",
      "setUserPresenceRequired",
      "setIsStrongBoxBacked",
    ];

    const intMethods = [
      "setKeySize",
      "setUserAuthenticationValidityDurationSeconds",
    ];

    for (const name of boolMethods) {
      try {
        hooks.push(hook(
          Builder[name].overload("boolean"),
          (original, self, args) => {
            const [value] = args;
            send({
              subject: "crypto",
              category: "keygen",
              symbol: `KeyGenParameterSpec.${name}`,
              dir: "enter",
              line: `Builder.${name}(${value})`,
              backtrace: javaBt(),
              extra: { method: name, value: String(value) },
            } satisfies BaseMessage);
            return original.call(self, value);
          },
        ));
      } catch (_) {
        /* not available on this API level */
      }
    }

    for (const name of intMethods) {
      try {
        hooks.push(hook(
          Builder[name].overload("int"),
          (original, self, args) => {
            const [value] = args;
            send({
              subject: "crypto",
              category: "keygen",
              symbol: `KeyGenParameterSpec.${name}`,
              dir: "enter",
              line: `Builder.${name}(${value})`,
              backtrace: javaBt(),
              extra: { method: name, value: String(value) },
            } satisfies BaseMessage);
            return original.call(self, value);
          },
        ));
      } catch (_) {
        /* not available on this API level */
      }
    }
  });

  return hooks;
}

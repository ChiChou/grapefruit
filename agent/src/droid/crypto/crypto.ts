import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook as javaHook } from "@/common/hooks/java.js";

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

import { byteArrayToBuffer } from "@/droid/lib/jbytes.js";

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
    hooks.push(
      javaHook(
        Cipher,
        "getInstance",
        ["java.lang.String"],
        function (transformation) {
          const result = this.getInstance(transformation);
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
      ),
    );

    // getInstance(String, String)
    hooks.push(
      javaHook(
        Cipher,
        "getInstance",
        ["java.lang.String", "java.lang.String"],
        function (transformation, provider) {
          const result = this.getInstance(transformation, provider);
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
      ),
    );

    // init(int, Key)
    hooks.push(
      javaHook(
        Cipher,
        "init",
        ["int", "java.security.Key"],
        function (mode, key) {
          const op = CIPHER_MODES[mode] || String(mode);
          const algo = this.getAlgorithm();
          send({
            subject: "crypto",
            category: "cipher",
            symbol: "Cipher.init",
            dir: "enter",
            line: `Cipher.init(${op}, ${key.$className}) [${algo}]`,
            backtrace: javaBt(),
            extra: { op, algo },
          } satisfies BaseMessage);
          this.init(mode, key);
        },
      ),
    );

    // init(int, Key, AlgorithmParameterSpec)
    hooks.push(
      javaHook(
        Cipher,
        "init",
        [
          "int",
          "java.security.Key",
          "java.security.spec.AlgorithmParameterSpec",
        ],
        function (mode, key, spec) {
          const op = CIPHER_MODES[mode] || String(mode);
          const algo = this.getAlgorithm();
          send({
            subject: "crypto",
            category: "cipher",
            symbol: "Cipher.init",
            dir: "enter",
            line: `Cipher.init(${op}, ${key.$className}, ${spec.$className}) [${algo}]`,
            backtrace: javaBt(),
            extra: { op, algo },
          } satisfies BaseMessage);
          this.init(mode, key, spec);
        },
      ),
    );

    // doFinal()
    hooks.push(
      javaHook(Cipher, "doFinal", [], function () {
        const algo = this.getAlgorithm();
        send({
          subject: "crypto",
          category: "cipher",
          symbol: "Cipher.doFinal",
          dir: "enter",
          line: `Cipher.doFinal() [${algo}]`,
          backtrace: javaBt(),
          extra: { algo },
        } satisfies BaseMessage);
        const result = this.doFinal();
        const buf = toBuffer(result);
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
      }),
    );

    // doFinal(byte[])
    hooks.push(
      javaHook(Cipher, "doFinal", ["[B"], function (input) {
        const algo = this.getAlgorithm();
        const inBuf = toBuffer(input);
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
        const result = this.doFinal(input);
        const outBuf = toBuffer(result);
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
      }),
    );

    // update(byte[])
    hooks.push(
      javaHook(Cipher, "update", ["[B"], function (input) {
        const algo = this.getAlgorithm();
        const inBuf = toBuffer(input);
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
        const result = this.update(input);
        const outBuf = toBuffer(result);
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
      }),
    );
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
    hooks.push(
      javaHook(PBEKeySpec, "$init", ["[C"], function (pass) {
        const password = toStr(pass);
        send({
          subject: "crypto",
          category: "pbkdf",
          symbol: "PBEKeySpec",
          dir: "enter",
          line: `PBEKeySpec(pass="${password}")`,
          backtrace: javaBt(),
          extra: { password },
        } satisfies BaseMessage);
        this.$init(pass);
      }),
    );

    // PBEKeySpec(char[], byte[], int)
    hooks.push(
      javaHook(
        PBEKeySpec,
        "$init",
        ["[C", "[B", "int"],
        function (pass, salt, iter) {
          const password = toStr(pass);
          const saltBuf = toBuffer(salt);
          send(
            {
              subject: "crypto",
              category: "pbkdf",
              symbol: "PBEKeySpec",
              dir: "enter",
              line: `PBEKeySpec(pass="${password}", salt[${salt?.length ?? 0}B], iter=${iter})`,
              backtrace: javaBt(),
              extra: {
                password,
                iterations: iter,
                detailType: "salt",
                len: salt?.length ?? 0,
              },
            } satisfies BaseMessage,
            saltBuf,
          );
          this.$init(pass, salt, iter);
        },
      ),
    );

    // PBEKeySpec(char[], byte[], int, int)
    hooks.push(
      javaHook(
        PBEKeySpec,
        "$init",
        ["[C", "[B", "int", "int"],
        function (pass, salt, iter, keyLen) {
          const password = toStr(pass);
          const saltBuf = toBuffer(salt);
          send(
            {
              subject: "crypto",
              category: "pbkdf",
              symbol: "PBEKeySpec",
              dir: "enter",
              line: `PBEKeySpec(pass="${password}", salt[${salt?.length ?? 0}B], iter=${iter}, keyLen=${keyLen})`,
              backtrace: javaBt(),
              extra: {
                password,
                iterations: iter,
                keyLength: keyLen,
                detailType: "salt",
                len: salt?.length ?? 0,
              },
            } satisfies BaseMessage,
            saltBuf,
          );
          this.$init(pass, salt, iter, keyLen);
        },
      ),
    );
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
        hooks.push(
          javaHook(Builder, name, ["boolean"], function (value) {
            send({
              subject: "crypto",
              category: "keygen",
              symbol: `KeyGenParameterSpec.${name}`,
              dir: "enter",
              line: `Builder.${name}(${value})`,
              backtrace: javaBt(),
              extra: { method: name, value: String(value) },
            } satisfies BaseMessage);
            return this[name](value);
          }),
        );
      } catch (_) {
        /* not available on this API level */
      }
    }

    for (const name of intMethods) {
      try {
        hooks.push(
          javaHook(Builder, name, ["int"], function (value) {
            send({
              subject: "crypto",
              category: "keygen",
              symbol: `KeyGenParameterSpec.${name}`,
              dir: "enter",
              line: `Builder.${name}(${value})`,
              backtrace: javaBt(),
              extra: { method: name, value: String(value) },
            } satisfies BaseMessage);
            return this[name](value);
          }),
        );
      } catch (_) {
        /* not available on this API level */
      }
    }
  });

  return hooks;
}

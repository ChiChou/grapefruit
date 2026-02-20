import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { patch as createPatch, backtrace } from "@/common/hooks/java.js";

const restores: Array<() => void> = [];
let running = false;

const patch = createPatch(restores);


export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    try {
      hookSharedPreferencesRead();
    } catch (e) {
      console.warn("sharedpref: read hooks unavailable:", e);
    }

    try {
      hookSharedPreferencesWrite();
    } catch (e) {
      console.warn("sharedpref: write hooks unavailable:", e);
    }

    try {
      hookGetSharedPreferences();
    } catch (e) {
      console.warn("sharedpref: getSharedPreferences hook unavailable:", e);
    }
  });
}

function hookGetSharedPreferences() {
  const ContextWrapper = Java.use("android.content.ContextWrapper");

  patch(
    ContextWrapper.getSharedPreferences.overload("java.lang.String", "int"),
    (original, self, args) => {
      const [name, mode] = args as [Java.Wrapper, number];
      const prefName = name?.toString() ?? "<null>";

      send({
        subject: "hook",
        category: "sharedpref",
        symbol: "Context.getSharedPreferences",
        dir: "enter",
        line: `getSharedPreferences("${prefName}", ${mode})`,
        backtrace: backtrace(),
        extra: { op: "open", name: prefName, mode },
      } satisfies BaseMessage);

      return original.call(self, name, mode);
    },
  );
}

function hookSharedPreferencesRead() {
  const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");

  const readMethods = [
    { name: "getString", argType: "java.lang.String", valueType: "string" },
    { name: "getInt", argType: "int", valueType: "int" },
    { name: "getLong", argType: "long", valueType: "long" },
    { name: "getFloat", argType: "float", valueType: "float" },
    { name: "getBoolean", argType: "boolean", valueType: "boolean" },
  ] as const;

  for (const { name, argType, valueType } of readMethods) {
    try {
      patch(
        SharedPreferencesImpl[name].overload("java.lang.String", argType),
        (original, self, args) => {
          const [key, defValue] = args as [Java.Wrapper, unknown];
          const keyStr = key?.toString() ?? "<null>";
          const ret = original.call(self, key, defValue);

          send({
            subject: "hook",
            category: "sharedpref",
            symbol: `SharedPreferences.${name}`,
            dir: "leave",
            line: `${name}("${keyStr}") => ${ret}`,
            backtrace: backtrace(),
            extra: {
              op: "read",
              method: name,
              key: keyStr,
              value: ret?.toString() ?? null,
              valueType,
            },
          } satisfies BaseMessage);

          return ret;
        },
      );
    } catch { /* overload may not exist */ }
  }

  // getStringSet
  try {
    patch(
      SharedPreferencesImpl.getStringSet.overload("java.lang.String", "java.util.Set"),
      (original, self, args) => {
        const [key, defValue] = args as [Java.Wrapper, Java.Wrapper | null];
        const keyStr = key?.toString() ?? "<null>";
        const ret = original.call(self, key, defValue);

        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.getStringSet",
          dir: "leave",
          line: `getStringSet("${keyStr}")`,
          backtrace: backtrace(),
          extra: { op: "read", method: "getStringSet", key: keyStr, valueType: "stringSet" },
        } satisfies BaseMessage);

        return ret;
      },
    );
  } catch { /* may not exist */ }

  // getAll
  try {
    patch(
      SharedPreferencesImpl.getAll,
      (original, self, args) => {
        const ret = original.call(self, ...args);

        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.getAll",
          dir: "leave",
          line: "getAll()",
          backtrace: backtrace(),
          extra: { op: "read", method: "getAll" },
        } satisfies BaseMessage);

        return ret;
      },
    );
  } catch { /* may not exist */ }

  // contains
  try {
    patch(
      SharedPreferencesImpl.contains.overload("java.lang.String"),
      (original, self, args) => {
        const [key] = args as [Java.Wrapper];
        const keyStr = key?.toString() ?? "<null>";
        const ret = original.call(self, key);

        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.contains",
          dir: "leave",
          line: `contains("${keyStr}") => ${ret}`,
          backtrace: backtrace(),
          extra: { op: "query", method: "contains", key: keyStr, result: ret },
        } satisfies BaseMessage);

        return ret;
      },
    );
  } catch { /* may not exist */ }
}

function hookSharedPreferencesWrite() {
  const EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

  const writeMethods = [
    { name: "putString", argType: "java.lang.String", valueType: "string" },
    { name: "putInt", argType: "int", valueType: "int" },
    { name: "putLong", argType: "long", valueType: "long" },
    { name: "putFloat", argType: "float", valueType: "float" },
    { name: "putBoolean", argType: "boolean", valueType: "boolean" },
  ] as const;

  for (const { name, argType, valueType } of writeMethods) {
    try {
      patch(
        EditorImpl[name].overload("java.lang.String", argType),
        (original, self, args) => {
          const [key, value] = args as [Java.Wrapper, unknown];
          const keyStr = key?.toString() ?? "<null>";
          const valStr = value?.toString() ?? "null";

          send({
            subject: "hook",
            category: "sharedpref",
            symbol: `SharedPreferences.Editor.${name}`,
            dir: "enter",
            line: `${name}("${keyStr}", ${valStr})`,
            backtrace: backtrace(),
            extra: { op: "write", method: name, key: keyStr, value: valStr, valueType },
          } satisfies BaseMessage);

          return original.call(self, key, value);
        },
      );
    } catch { /* overload may not exist */ }
  }

  // putStringSet
  try {
    patch(
      EditorImpl.putStringSet.overload("java.lang.String", "java.util.Set"),
      (original, self, args) => {
        const [key, values] = args as [Java.Wrapper, Java.Wrapper | null];
        const keyStr = key?.toString() ?? "<null>";

        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.Editor.putStringSet",
          dir: "enter",
          line: `putStringSet("${keyStr}", ...)`,
          backtrace: backtrace(),
          extra: { op: "write", method: "putStringSet", key: keyStr, valueType: "stringSet" },
        } satisfies BaseMessage);

        return original.call(self, key, values);
      },
    );
  } catch { /* may not exist */ }

  // remove
  try {
    patch(
      EditorImpl.remove.overload("java.lang.String"),
      (original, self, args) => {
        const [key] = args as [Java.Wrapper];
        const keyStr = key?.toString() ?? "<null>";

        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.Editor.remove",
          dir: "enter",
          line: `remove("${keyStr}")`,
          backtrace: backtrace(),
          extra: { op: "delete", method: "remove", key: keyStr },
        } satisfies BaseMessage);

        return original.call(self, key);
      },
    );
  } catch { /* may not exist */ }

  // clear
  try {
    patch(
      EditorImpl.clear,
      (original, self, args) => {
        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.Editor.clear",
          dir: "enter",
          line: "clear()",
          backtrace: backtrace(),
          extra: { op: "delete", method: "clear" },
        } satisfies BaseMessage);

        return original.call(self, ...args);
      },
    );
  } catch { /* may not exist */ }

  // commit
  try {
    patch(
      EditorImpl.commit,
      (original, self, args) => {
        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.Editor.commit",
          dir: "enter",
          line: "commit() // sync write",
          backtrace: backtrace(),
          extra: { op: "commit", method: "commit", sync: true },
        } satisfies BaseMessage);

        return original.call(self, ...args);
      },
    );
  } catch { /* may not exist */ }

  // apply
  try {
    patch(
      EditorImpl.apply,
      (original, self, args) => {
        send({
          subject: "hook",
          category: "sharedpref",
          symbol: "SharedPreferences.Editor.apply",
          dir: "enter",
          line: "apply() // async write",
          backtrace: backtrace(),
          extra: { op: "commit", method: "apply", sync: false },
        } satisfies BaseMessage);

        return original.call(self, ...args);
      },
    );
  } catch { /* may not exist */ }
}

export function stop() {
  Java.perform(() => {
    for (let i = restores.length - 1; i >= 0; i--) {
      try {
        restores[i]();
      } catch { /* ignore */ }
    }
  });
  restores.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  if (!Java.available) return false;
  let found = false;
  Java.perform(() => {
    try {
      Java.use("android.app.SharedPreferencesImpl");
      found = true;
    } catch { /* not found */ }
  });
  return found;
}

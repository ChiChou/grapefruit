import Java from "frida-java-bridge";

export function toJS(obj: Java.Wrapper | null): unknown {
  if (obj === null) return null;

  const cls = obj.$className;

  if (cls === "java.lang.String") return obj.toString();
  if (cls === "java.lang.Boolean") return !!obj.booleanValue();
  if (
    cls === "java.lang.Integer" ||
    cls === "java.lang.Long" ||
    cls === "java.lang.Short" ||
    cls === "java.lang.Byte" ||
    cls === "java.lang.Float" ||
    cls === "java.lang.Double"
  ) {
    return Number(obj);
  }

  if (cls === "[B") {
    const ReflectArray = Java.use("java.lang.reflect.Array");
    const length = ReflectArray.getLength(obj);
    const cap = Math.min(length, 256);
    const bytes: number[] = [];
    for (let i = 0; i < cap; i++) {
      bytes.push(Number(ReflectArray.get(obj, i)) & 0xff);
    }
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  if (Java.use("java.util.Map").class.isInstance(obj)) {
    const result: Record<string, unknown> = {};
    const it = obj.entrySet().iterator();
    let count = 0;
    while (it.hasNext() && count < 64) {
      const e = it.next();
      result[e.getKey().toString()] = toJS(e.getValue());
      count++;
    }
    return result;
  }

  if (Java.use("java.util.List").class.isInstance(obj)) {
    const result: unknown[] = [];
    const size = Math.min(obj.size(), 64);
    for (let i = 0; i < size; i++) {
      result.push(toJS(obj.get(i)));
    }
    return result;
  }

  return obj.toString();
}

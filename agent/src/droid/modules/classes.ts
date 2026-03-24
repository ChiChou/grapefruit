import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";

export interface JavaMethod {
  name: string;
  returnType: string;
  argumentTypes: string[];
  isStatic: boolean;
}

export interface JavaField {
  name: string;
  type: string;
  isStatic: boolean;
}

export interface JavaClassDetail {
  name: string;
  superClass: string | null;
  interfaces: string[];
  methods: JavaMethod[];
  ownMethods: string[];
  fields: JavaField[];
}

export function list() {
  if (!Java.available)
    throw new Error("Java runtime is not available in this process");
  return perform(() => Java.enumerateLoadedClassesSync());
}

export function inspect(name: string) {
  return perform(() => {
    const wrapper = Java.use(name);
    const jClass = wrapper.class;

    // Superclass
    const superObj = jClass.getSuperclass();
    const superClass = superObj ? superObj.getName() : null;

    // Interfaces
    const ifaces = jClass.getInterfaces();
    const interfaces: string[] = [];
    for (let i = 0; i < ifaces.length; i++) {
      interfaces.push(ifaces[i].getName());
    }

    // Declared methods (own)
    const declaredMethods = jClass.getDeclaredMethods();
    const methods: JavaMethod[] = [];
    const ownMethods: string[] = [];
    const Modifier = Java.use("java.lang.reflect.Modifier");

    for (let i = 0; i < declaredMethods.length; i++) {
      const m = declaredMethods[i];
      const mName = m.getName();
      const retType = m.getReturnType().getName();
      const paramTypes = m.getParameterTypes();
      const argTypes: string[] = [];
      for (let j = 0; j < paramTypes.length; j++) {
        argTypes.push(paramTypes[j].getName());
      }
      const mods = m.getModifiers();
      const isStatic = Modifier.isStatic(mods);

      methods.push({
        name: mName,
        returnType: retType,
        argumentTypes: argTypes,
        isStatic,
      });
      ownMethods.push(mName);
    }

    // Declared fields
    const declaredFields = jClass.getDeclaredFields();
    const fields: JavaField[] = [];
    for (let i = 0; i < declaredFields.length; i++) {
      const f = declaredFields[i];
      const fMods = f.getModifiers();
      fields.push({
        name: f.getName(),
        type: f.getType().getName(),
        isStatic: Modifier.isStatic(fMods),
      });
    }

    return {
      name,
      superClass,
      interfaces,
      methods,
      ownMethods,
      fields,
    } as JavaClassDetail;
  });
}

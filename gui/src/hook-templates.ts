export type SymbolKind = 'function' | 'variable' | 'class'

export interface Import {
  address: string;
  name: string;
  demangled: string;
  type: SymbolKind;
}

export interface Group {
  path: string;
  imps: Import[];
  expanded: boolean;
  loading: boolean;
}

export interface Export {
  name: string;
  address: string;
  type: SymbolKind;
  demangled?: string;
}

export interface Exports {
  count: number;
  list: Export[];
}

export interface AppSymbol {
  name: string;
  demangled?: string;
  global: boolean;
  address: string;
  type?: SymbolKind;
}

export interface Symbols {
  count: number;
  list: AppSymbol[];
}

export interface HookInfo {
  module: string | null;
  name: string;
}

function* c(list: HookInfo[]) {
  for (const item of list) {
    const mod = JSON.stringify(item.module) // allows null
    yield `
Interceptor.attach(Module.getExportByName(${mod}, "${item.name}"), {
    onEnter(args) {
        // todo: add code here
        console.log("${item.name} has been called");
        // console.log('${item.name} called from:\\n' +
        //     Thread.backtrace(this.context, Backtracer.ACCURATE)
        //     .map(DebugSymbol.fromAddress).join('\\n') + '\\n');
    },
    onLeave(retval) {

    },
});
`
  }
}

export interface ObjCHookInfo {
  class: string;
  method: string;
}

function* objc(list: ObjCHookInfo[]) {
  for (const item of list) {
    const sign = item.method.charAt(0)
    const tail = item.method.substring(1)
    const target = `ObjC.classes['${item.class}']['${item.method}']`
    yield `
Interceptor.attach(${target}.implementation, {
    onEnter(args) {
        // console.log('${sign}[${item.class} ${tail}] called from:\\n' +
        //     Thread.backtrace(this.context, Backtracer.ACCURATE)
        //     .map(DebugSymbol.fromAddress).join('\\n') + '\\n');
    },
    onLeave(retVal) {

    }
})
`
  }
}

function* swizzling(list: ObjCHookInfo[]) {
  for (const item of list) {
    yield `
const method = ObjC.classes['${item.class}']['${item.method}'];
const original = method.implementation;
method.implementation = ObjC.implement(method, () => {
    // todo: add code here
});
`
  }
}

export function pointer(mod: string, name: string): string {
  return `Module.findExportByName('${mod}', '${name}').readPointer();`
}

export function render(
  template: 'c' | 'objc' | 'swizzling',
  list: Array<HookInfo | ObjCHookInfo>
): string {
  const body = () => {
    if (template === 'c') {
      return c(list as HookInfo[])
    } else if (template === 'objc') {
      return objc(list as ObjCHookInfo[])
    } else if (template === 'swizzling') {
      return swizzling(list as ObjCHookInfo[])
    }
  }

  return [...body() as Iterable<string>].join('\n')
}

import { parseArgs } from "node:util";
import { rest } from "./client.ts";
import { agent, type SessionParams } from "./rpc.ts";
import type { Platform } from "../types.ts";

type ClientOptions = { host?: string; port?: number };

const globalOpts = {
  host: { type: "string", short: "H", default: "localhost" },
  port: { type: "string", short: "p", default: "31337" },
  help: { type: "boolean", short: "h" },
} as const;

const sessionOpts = {
  device: { type: "string", short: "d" },
  platform: { type: "string" },
  bundle: { type: "string", short: "b" },
  pid: { type: "string" },
  name: { type: "string", short: "n" },
} as const;

function getClientOpts(values: Record<string, unknown>): ClientOptions {
  return {
    host: values.host as string | undefined,
    port: values.port ? parseInt(values.port as string, 10) : undefined,
  };
}

function getSessionParams(values: Record<string, unknown>): SessionParams {
  const platform = values.platform as Platform;
  const mode = values.bundle ? "app" : "daemon";
  return {
    device: values.device as string,
    platform,
    mode,
    bundle: values.bundle as string | undefined,
    pid: values.pid ? parseInt(values.pid as string, 10) : undefined,
    name: values.name as string | undefined,
  };
}

function exitErr(msg: string): never {
  console.error(msg);
  process.exit(1);
}

function requireSession(values: Record<string, unknown>): SessionParams {
  if (!values.device) exitErr("Error: --device is required");
  if (!values.platform) exitErr("Error: --platform is required (droid|fruity)");
  if (values.platform !== "droid" && values.platform !== "fruity") {
    exitErr("Error: --platform must be 'droid' or 'fruity'");
  }
  if (!values.bundle && !values.pid) exitErr("Error: --bundle or --pid is required");
  return getSessionParams(values);
}

function printJson(data: unknown) {
  console.log(JSON.stringify(data, null, 2));
}

export async function runCLI(argv: string[]) {
  const args = parseArgs({
    args: argv,
    options: { ...globalOpts, ...sessionOpts },
    allowPositionals: true,
    strict: false,
  });

  const { positionals, values } = args;
  const opts = getClientOpts(values);

  if (positionals.length === 0) {
    printHelp();
    process.exit(1);
  }

  if (values.help && positionals[0] !== "setup") {
    printHelp();
    process.exit(0);
  }

  const [cmd, ...subArgs] = positionals;

  switch (cmd) {
    case "version":
      printJson(await rest.version(opts));
      break;

    case "device":
      await runDeviceCmd(subArgs[0], subArgs.slice(1), opts);
      break;

    case "log":
      await runLogCmd(subArgs[0], subArgs.slice(1), values, opts);
      break;

    case "history":
      await runHistoryCmd(subArgs[0], subArgs.slice(1), values, opts);
      break;

    case "agent": {
      const session = requireSession(values);
      await runAgentCmd(subArgs[0], subArgs.slice(1), session, opts);
      break;
    }

    case "setup": {
      const { runSetup } = await import("./setup.ts");
      await runSetup(argv.slice(1));
      break;
    }

    default:
      exitErr(`Unknown command: ${cmd}`);
  }
}

async function runDeviceCmd(sub: string | undefined, args: string[], opts: ClientOptions) {
  if (!sub) exitErr("device requires subcommand: list|apps|ps|info|kill");
  const [device, pid] = args;

  switch (sub) {
    case "list":
      printJson(await rest.devices(opts));
      break;
    case "apps":
      if (!device) exitErr("device apps requires <device>");
      printJson(await rest.apps(device, opts));
      break;
    case "ps":
      if (!device) exitErr("device ps requires <device>");
      printJson(await rest.processes(device, opts));
      break;
    case "info":
      if (!device) exitErr("device info requires <device>");
      printJson(await rest.deviceInfo(device, opts));
      break;
    case "kill":
      if (!device || !pid) exitErr("device kill requires <device> <pid>");
      await rest.kill(device, parseInt(pid, 10), opts);
      console.log("Process killed");
      break;
    default:
      exitErr(`Unknown device subcommand: ${sub}`);
  }
}

async function runLogCmd(
  sub: string | undefined,
  args: string[],
  values: Record<string, unknown>,
  opts: ClientOptions
) {
  if (!sub) exitErr("log requires subcommand: hooks|crypto|syslog|agent|clear");
  const [device, id] = args;
  if (!device || !id) exitErr(`log ${sub} requires <device> <identifier>`);
  const limit = parseInt((values.limit as string) || "100", 10);

  switch (sub) {
    case "hooks":
      printJson(await rest.hooks(device, id, limit, opts));
      break;
    case "crypto":
      printJson(await rest.crypto(device, id, limit, opts));
      break;
    case "syslog":
      console.log(await rest.syslog(device, id, opts));
      break;
    case "agent":
      console.log(await rest.agentLog(device, id, opts));
      break;
    case "clear":
      await rest.clearLogs(device, id, opts);
      console.log("Logs cleared");
      break;
    default:
      exitErr(`Unknown log subcommand: ${sub}`);
  }
}

async function runHistoryCmd(
  sub: string | undefined,
  args: string[],
  values: Record<string, unknown>,
  opts: ClientOptions
) {
  if (!sub) exitErr("history requires subcommand: http|nsurl|jni|flutter|xpc|privacy|hermes");
  const [device, id] = args;
  if (!device || !id) exitErr(`history ${sub} requires <device> <identifier>`);
  const limit = parseInt((values.limit as string) || "100", 10);

  switch (sub) {
    case "http":
      printJson(await rest.http(device, id, limit, opts));
      break;
    case "nsurl":
      printJson(await rest.nsurl(device, id, limit, opts));
      break;
    case "jni":
      printJson(await rest.jni(device, id, limit, opts));
      break;
    case "flutter":
      printJson(await rest.flutter(device, id, limit, opts));
      break;
    case "xpc":
      printJson(await rest.xpc(device, id, limit, opts));
      break;
    case "privacy":
      printJson(await rest.privacy(device, id, limit, opts));
      break;
    case "hermes":
      printJson(await rest.hermes(device, id, limit, opts));
      break;
    default:
      exitErr(`Unknown history subcommand: ${sub}`);
  }
}

async function runAgentCmd(
  ns: string | undefined,
  args: string[],
  s: SessionParams,
  opts: ClientOptions
) {
  if (!ns) exitErr("agent requires namespace");

  switch (ns) {
    case "fs":
      await runFsCmd(args[0], args.slice(1), s, opts);
      break;
    case "app":
      await runAppCmd(args[0], s, opts);
      break;
    case "checksec":
      await runChecksecCmd(args[0], args[1], s, opts);
      break;
    case "class":
      await runClassCmd(args[0], args[1], s, opts);
      break;
    case "classdump":
      await runClassdumpCmd(args[0], args[1], s, opts);
      break;
    case "hook":
      await runHookCmd(args[0], args[1], s, opts);
      break;
    case "crypto":
      await runCryptoCmd(args[0], args[1], s, opts);
      break;
    case "pin":
      await runPinCmd(args[0], args[1], s, opts);
      break;
    case "symbol":
      await runSymbolCmd(args[0], args.slice(1), s, opts);
      break;
    case "thread":
      printJson(await agent.thread.list(s, opts));
      break;
    case "memory":
      await runMemoryCmd(args[0], args.slice(1), s, opts);
      break;
    case "lsof":
      printJson(await agent.lsof(s, opts));
      break;
    case "sqlite":
      await runSqliteCmd(args[0], args[1], args[2], s, opts);
      break;
    case "il2cpp":
      await runIl2cppCmd(args[0], args[1], s, opts);
      break;
    case "android":
      await runAndroidCmd(args[0], args.slice(1), s, opts);
      break;
    case "ios":
      await runIosCmd(args[0], args.slice(1), s, opts);
      break;
    case "eval":
      if (!args[0]) exitErr("agent eval requires <code>");
      printJson(await agent.script.eval(s, args[0], opts));
      break;
    case "rn":
      await runRnCmd(args[0], args.slice(1), s, opts);
      break;
    case "native":
      await runNativeCmd(args[0], args[1], args[2], s, opts);
      break;
    default:
      exitErr(`Unknown agent namespace: ${ns}`);
  }
}

async function runFsCmd(sub: string | undefined, args: string[], s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent fs requires subcommand: ls|cat|data|plist|preview|rm|cp|mv|mkdir|stat|access|roots|write");
  switch (sub) {
    case "ls":
      if (!args[0]) exitErr("agent fs ls requires <path>");
      printJson(await agent.fs.ls(s, args[0], opts));
      break;
    case "cat":
      if (!args[0]) exitErr("agent fs cat requires <path>");
      console.log(await agent.fs.cat(s, args[0], opts));
      break;
    case "data":
      if (!args[0]) exitErr("agent fs data requires <path>");
      printJson(await agent.fs.data(s, args[0], opts));
      break;
    case "plist":
      if (!args[0]) exitErr("agent fs plist requires <path>");
      printJson(await agent.fs.plist(s, args[0], opts));
      break;
    case "preview":
      if (!args[0]) exitErr("agent fs preview requires <path>");
      printJson(await agent.fs.preview(s, args[0], opts));
      break;
    case "rm":
      if (!args[0]) exitErr("agent fs rm requires <path>");
      await agent.fs.rm(s, args[0], opts);
      console.log("Deleted");
      break;
    case "cp":
      if (!args[0] || !args[1]) exitErr("agent fs cp requires <src> <dst>");
      await agent.fs.cp(s, args[0], args[1], opts);
      console.log("Copied");
      break;
    case "mv":
      if (!args[0] || !args[1]) exitErr("agent fs mv requires <src> <dst>");
      await agent.fs.mv(s, args[0], args[1], opts);
      console.log("Moved");
      break;
    case "mkdir":
      if (!args[0]) exitErr("agent fs mkdir requires <path>");
      await agent.fs.mkdir(s, args[0], opts);
      console.log("Created");
      break;
    case "stat":
      if (!args[0]) exitErr("agent fs stat requires <path>");
      printJson(await agent.fs.stat(s, args[0], opts));
      break;
    case "access":
      if (!args[0]) exitErr("agent fs access requires <path>");
      printJson(await agent.fs.access(s, args[0], opts));
      break;
    case "roots":
      printJson(await agent.fs.roots(s, opts));
      break;
    case "write":
      if (!args[0] || !args[1]) exitErr("agent fs write requires <path> <content>");
      await agent.fs.saveText(s, args[0], args[1], opts);
      console.log("Written");
      break;
    default:
      exitErr(`Unknown agent fs subcommand: ${sub}`);
  }
}

async function runAppCmd(sub: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent app requires subcommand: info|manifest|entitlements|urls|plist|process-info");
  switch (sub) {
    case "info":
      printJson(await agent.app.info(s, opts));
      break;
    case "manifest":
      console.log(await agent.app.manifest(s, opts));
      break;
    case "entitlements":
      console.log(await agent.app.entitlements(s, opts));
      break;
    case "urls":
      printJson(await agent.app.urls(s, opts));
      break;
    case "plist":
      printJson(await agent.app.plist(s, opts));
      break;
    case "process-info":
      printJson(await agent.app.processInfo(s, opts));
      break;
    default:
      exitErr(`Unknown agent app subcommand: ${sub}`);
  }
}

async function runChecksecCmd(sub: string | undefined, name: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent checksec requires subcommand: all|main|single");
  switch (sub) {
    case "all":
      printJson(await agent.checksec.all(s, opts));
      break;
    case "main":
      printJson(await agent.checksec.main(s, opts));
      break;
    case "single":
      if (!name) exitErr("agent checksec single requires <name>");
      printJson(await agent.checksec.single(s, name, opts));
      break;
    default:
      exitErr(`Unknown agent checksec subcommand: ${sub}`);
  }
}

async function runClassCmd(sub: string | undefined, name: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent class requires subcommand: list|inspect|constants");
  switch (sub) {
    case "list":
      printJson(await agent.class.list(s, opts));
      break;
    case "inspect":
      if (!name) exitErr("agent class inspect requires <name>");
      printJson(await agent.class.inspect(s, name, opts));
      break;
    case "constants":
      if (!name) exitErr("agent class constants requires <name>");
      printJson(await agent.class.constants(s, name, opts));
      break;
    default:
      exitErr(`Unknown agent class subcommand: ${sub}`);
  }
}

async function runClassdumpCmd(sub: string | undefined, name: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent classdump requires subcommand: list|module|inheritance|inspect");
  switch (sub) {
    case "list":
      printJson(await agent.classdump.list(s, opts));
      break;
    case "module":
      if (!name) exitErr("agent classdump module requires <module>");
      printJson(await agent.classdump.classesForModule(s, name, opts));
      break;
    case "inheritance":
      if (!name) exitErr("agent classdump inheritance requires <name>");
      printJson(await agent.classdump.inheritance(s, name, opts));
      break;
    case "inspect":
      if (!name) exitErr("agent classdump inspect requires <name>");
      printJson(await agent.classdump.inspect(s, name, opts));
      break;
    default:
      exitErr(`Unknown agent classdump subcommand: ${sub}`);
  }
}

async function runHookCmd(sub: string | undefined, group: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent hook requires subcommand: list|status|start|stop|user-hooks");
  switch (sub) {
    case "list":
      printJson(await agent.hook.list(s, opts));
      break;
    case "status":
      printJson(await agent.hook.status(s, opts));
      break;
    case "start":
      if (!group) exitErr("agent hook start requires <group>");
      await agent.hook.start(s, group, opts);
      console.log("Hook started");
      break;
    case "stop":
      if (!group) exitErr("agent hook stop requires <group>");
      await agent.hook.stop(s, group, opts);
      console.log("Hook stopped");
      break;
    case "user-hooks":
      printJson(await agent.hook.userHooks(s, opts));
      break;
    default:
      exitErr(`Unknown agent hook subcommand: ${sub}`);
  }
}

async function runCryptoCmd(sub: string | undefined, group: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent crypto requires subcommand: status|available|start|stop");
  switch (sub) {
    case "status":
      printJson(await agent.crypto.status(s, opts));
      break;
    case "available":
      printJson(await agent.crypto.available(s, opts));
      break;
    case "start":
      if (!group) exitErr("agent crypto start requires <group>");
      await agent.crypto.start(s, group, opts);
      console.log("Crypto hook started");
      break;
    case "stop":
      if (!group) exitErr("agent crypto stop requires <group>");
      await agent.crypto.stop(s, group, opts);
      console.log("Crypto hook stopped");
      break;
    default:
      exitErr(`Unknown agent crypto subcommand: ${sub}`);
  }
}

async function runPinCmd(sub: string | undefined, id: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent pin requires subcommand: list|active|available|start|stop|snapshot|restore");
  switch (sub) {
    case "list":
      printJson(await agent.pin.list(s, opts));
      break;
    case "active":
      printJson(await agent.pin.active(s, opts));
      break;
    case "available":
      printJson(await agent.pin.available(s, opts));
      break;
    case "start":
      if (!id) exitErr("agent pin start requires <id>");
      await agent.pin.start(s, id, opts);
      console.log("Pin started");
      break;
    case "stop":
      if (!id) exitErr("agent pin stop requires <id>");
      await agent.pin.stop(s, id, opts);
      console.log("Pin stopped");
      break;
    case "snapshot":
      printJson(await agent.pin.snapshot(s, opts));
      break;
    default:
      exitErr(`Unknown agent pin subcommand: ${sub}`);
  }
}

async function runSymbolCmd(sub: string | undefined, args: string[], s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent symbol requires subcommand: modules|exports|imports|imports-grouped|strings|symbols|deps|sections|resolve|symbolicate");
  const mod = args[0];
  switch (sub) {
    case "modules":
      printJson(await agent.symbol.modules(s, opts));
      break;
    case "exports":
      if (!mod) exitErr("agent symbol exports requires <module>");
      printJson(await agent.symbol.exports(s, mod, opts));
      break;
    case "imports":
      if (!mod) exitErr("agent symbol imports requires <module>");
      printJson(await agent.symbol.imports(s, mod, opts));
      break;
    case "imports-grouped":
      if (!mod) exitErr("agent symbol imports-grouped requires <module>");
      printJson(await agent.symbol.importsGrouped(s, mod, opts));
      break;
    case "strings":
      if (!mod) exitErr("agent symbol strings requires <module>");
      printJson(await agent.symbol.strings(s, mod, opts));
      break;
    case "symbols":
      if (!mod) exitErr("agent symbol symbols requires <module>");
      printJson(await agent.symbol.symbols(s, mod, opts));
      break;
    case "deps":
      if (!mod) exitErr("agent symbol deps requires <module>");
      printJson(await agent.symbol.deps(s, mod, opts));
      break;
    case "sections":
      if (!mod) exitErr("agent symbol sections requires <module>");
      printJson(await agent.symbol.sections(s, mod, opts));
      break;
    case "resolve":
      if (!mod || !args[1]) exitErr("agent symbol resolve requires <module> <name>");
      printJson(await agent.symbol.resolve(s, mod, args[1], opts));
      break;
    case "symbolicate":
      if (!mod) exitErr("agent symbol symbolicate requires <addr>");
      printJson(await agent.symbol.symbolicate(s, mod, opts));
      break;
    default:
      exitErr(`Unknown agent symbol subcommand: ${sub}`);
  }
}

async function runMemoryCmd(sub: string | undefined, args: string[], s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent memory requires subcommand: dump|scan|stop-scan|ranges|info");
  switch (sub) {
    case "dump":
      if (!args[0] || !args[1]) exitErr("agent memory dump requires <addr> <size>");
      printJson(await agent.memory.dump(s, args[0], parseInt(args[1], 10), opts));
      break;
    case "scan":
      if (!args[0]) exitErr("agent memory scan requires <pattern>");
      printJson(await agent.memory.scan(s, args[0], opts));
      break;
    case "stop-scan":
      await agent.memory.stopScan(s, opts);
      console.log("Scan stopped");
      break;
    case "ranges":
      printJson(await agent.memory.ranges(s, opts));
      break;
    case "info":
      if (!args[0]) exitErr("agent memory info requires <addr>");
      printJson(await agent.memory.addressInfo(s, args[0], opts));
      break;
    default:
      exitErr(`Unknown agent memory subcommand: ${sub}`);
  }
}

async function runSqliteCmd(sub: string | undefined, path: string | undefined, table: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent sqlite requires subcommand: tables|dump");
  switch (sub) {
    case "tables":
      if (!path) exitErr("agent sqlite tables requires <path>");
      printJson(await agent.sqlite.tables(s, path, opts));
      break;
    case "dump":
      if (!path || !table) exitErr("agent sqlite dump requires <path> <table>");
      printJson(await agent.sqlite.dump(s, path, table, opts));
      break;
    default:
      exitErr(`Unknown agent sqlite subcommand: ${sub}`);
  }
}

async function runIl2cppCmd(sub: string | undefined, arg: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent il2cpp requires subcommand: available|info|assemblies|classes|search|detail|dump|gc-stats|gc-collect|gc-toggle|threads");
  switch (sub) {
    case "available":
      printJson(await agent.il2cpp.available(s, opts));
      break;
    case "info":
      printJson(await agent.il2cpp.info(s, opts));
      break;
    case "assemblies":
      printJson(await agent.il2cpp.assemblies(s, opts));
      break;
    case "classes":
      if (!arg) exitErr("agent il2cpp classes requires <assembly>");
      printJson(await agent.il2cpp.classes(s, arg, opts));
      break;
    case "search":
      if (!arg) exitErr("agent il2cpp search requires <query>");
      printJson(await agent.il2cpp.searchClasses(s, arg, opts));
      break;
    case "detail":
      if (!arg) exitErr("agent il2cpp detail requires <name>");
      printJson(await agent.il2cpp.classDetail(s, arg, opts));
      break;
    case "dump":
      if (!arg) exitErr("agent il2cpp dump requires <name>");
      printJson(await agent.il2cpp.classDump(s, arg, opts));
      break;
    case "gc-stats":
      printJson(await agent.il2cpp.gcStats(s, opts));
      break;
    case "gc-collect":
      await agent.il2cpp.gcCollect(s, opts);
      console.log("GC collected");
      break;
    case "gc-toggle":
      if (!arg) exitErr("agent il2cpp gc-toggle requires <on|off>");
      await agent.il2cpp.gcToggle(s, arg === "on", opts);
      console.log(`GC ${arg === "on" ? "enabled" : "disabled"}`);
      break;
    case "threads":
      printJson(await agent.il2cpp.threads(s, opts));
      break;
    default:
      exitErr(`Unknown agent il2cpp subcommand: ${sub}`);
  }
}

async function runAndroidCmd(sub: string | undefined, args: string[], s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent android requires subcommand");
  const arg = args[0];
  switch (sub) {
    case "activities":
      printJson(await agent.android.activities(s, opts));
      break;
    case "start-activity":
      if (!arg) exitErr("agent android start-activity requires <name>");
      await agent.android.startActivity(s, arg, opts);
      console.log("Activity started");
      break;
    case "services":
      printJson(await agent.android.services(s, opts));
      break;
    case "start-service":
      if (!arg) exitErr("agent android start-service requires <name>");
      await agent.android.startService(s, arg, opts);
      console.log("Service started");
      break;
    case "stop-service":
      if (!arg) exitErr("agent android stop-service requires <name>");
      await agent.android.stopService(s, arg, opts);
      console.log("Service stopped");
      break;
    case "receivers":
      printJson(await agent.android.receivers(s, opts));
      break;
    case "send-broadcast":
      if (!arg) exitErr("agent android send-broadcast requires <action>");
      await agent.android.sendBroadcast(s, arg, opts);
      console.log("Broadcast sent");
      break;
    case "providers":
      printJson(await agent.android.providers(s, opts));
      break;
    case "provider-query":
      if (!arg) exitErr("agent android provider-query requires <uri>");
      printJson(await agent.android.providerQuery(s, arg, opts));
      break;
    case "keystore":
      printJson(await agent.android.keystore(s, opts));
      break;
    case "keystore-info":
      if (!arg) exitErr("agent android keystore-info requires <alias>");
      printJson(await agent.android.keystoreInfo(s, arg, opts));
      break;
    case "keystore-cert":
      if (!arg) exitErr("agent android keystore-cert requires <alias>");
      printJson(await agent.android.keystoreCert(s, arg, opts));
      break;
    case "device-info":
      printJson(await agent.android.deviceInfo(s, opts));
      break;
    case "device-props":
      printJson(await agent.android.deviceProps(s, opts));
      break;
    case "resources":
      printJson(await agent.android.resources(s, opts));
      break;
    case "resource":
      if (!arg || !args[1]) exitErr("agent android resource requires <type> <name>");
      printJson(await agent.android.resource(s, arg, args[1], opts));
      break;
    case "webview":
      await runAndroidWebviewCmd(args.slice(0), s, opts);
      break;
    default:
      exitErr(`Unknown agent android subcommand: ${sub}`);
  }
}

async function runAndroidWebviewCmd(args: string[], s: SessionParams, opts: ClientOptions) {
  const sub = args[0];
  if (!sub || sub === "list") {
    printJson(await agent.android.webview.list(s, opts));
    return;
  }
  switch (sub) {
    case "debug":
      await agent.android.webview.setDebugging(s, true, opts);
      console.log("WebView debugging enabled");
      break;
    case "eval":
      if (!args[1] || !args[2]) exitErr("agent android webview eval requires <handle> <code>");
      printJson(await agent.android.webview.evaluate(s, args[1], args[2], opts));
      break;
    case "navigate":
      if (!args[1] || !args[2]) exitErr("agent android webview navigate requires <handle> <url>");
      await agent.android.webview.navigate(s, args[1], args[2], opts);
      console.log("Navigated");
      break;
    default:
      exitErr(`Unknown agent android webview subcommand: ${sub}`);
  }
}

async function runIosCmd(sub: string | undefined, args: string[], s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent ios requires subcommand");
  switch (sub) {
    case "keychain":
      printJson(await agent.ios.keychain(s, opts));
      break;
    case "keychain-remove":
      if (!args[0]) exitErr("agent ios keychain-remove requires <account>");
      await agent.ios.keychainRemove(s, args[0], opts);
      console.log("Removed");
      break;
    case "cookies":
      printJson(await agent.ios.cookies(s, opts));
      break;
    case "cookies-clear":
      await agent.ios.cookiesClear(s, opts);
      console.log("Cookies cleared");
      break;
    case "userdefaults":
      printJson(await agent.ios.userdefaults(s, opts));
      break;
    case "userdefaults-update":
      if (!args[0] || !args[1]) exitErr("agent ios userdefaults-update requires <key> <value>");
      await agent.ios.userdefaultsUpdate(s, args[0], args[1], opts);
      console.log("Updated");
      break;
    case "userdefaults-remove":
      if (!args[0]) exitErr("agent ios userdefaults-remove requires <key>");
      await agent.ios.userdefaultsRemove(s, args[0], opts);
      console.log("Removed");
      break;
    case "webviews":
      printJson(await agent.ios.webviews(s, opts));
      break;
    case "webviews-ui":
      printJson(await agent.ios.webviewsUI(s, opts));
      break;
    case "webview-eval":
      if (!args[0] || !args[1]) exitErr("agent ios webview-eval requires <handle> <code>");
      printJson(await agent.ios.webviewEval(s, args[0], args[1], opts));
      break;
    case "webview-navigate":
      if (!args[0] || !args[1]) exitErr("agent ios webview-navigate requires <handle> <url>");
      await agent.ios.webviewNavigate(s, args[0], args[1], opts);
      console.log("Navigated");
      break;
    case "jsc":
      printJson(await agent.ios.jsc(s, opts));
      break;
    case "jsc-dump":
      if (!args[0]) exitErr("agent ios jsc-dump requires <handle>");
      printJson(await agent.ios.jscDump(s, args[0], opts));
      break;
    case "jsc-run":
      if (!args[0] || !args[1]) exitErr("agent ios jsc-run requires <handle> <code>");
      printJson(await agent.ios.jscRun(s, args[0], args[1], opts));
      break;
    case "geolocation":
      if (!args[0] || !args[1]) exitErr("agent ios geolocation requires <lat> <lng>");
      await agent.ios.geolocation(s, parseFloat(args[0]), parseFloat(args[1]), opts);
      console.log("GPS spoofed");
      break;
    case "geolocation-dismiss":
      await agent.ios.geolocationDismiss(s, opts);
      console.log("GPS spoofing dismissed");
      break;
    case "uidevice":
      printJson(await agent.ios.uidevice(s, opts));
      break;
    case "open-url":
      if (!args[0]) exitErr("agent ios open-url requires <url>");
      await agent.ios.openUrl(s, args[0], opts);
      console.log("URL opened");
      break;
    case "ui-dump":
      printJson(await agent.ios.ui.dump(s, opts));
      break;
    case "ui-highlight":
      if (!args[0]) exitErr("agent ios ui-highlight requires <addr>");
      await agent.ios.ui.highlight(s, args[0], opts);
      console.log("Highlighted");
      break;
    case "ui-dismiss":
      await agent.ios.ui.dismissHighlight(s, opts);
      console.log("Dismissed");
      break;
    case "plugins":
      printJson(await agent.ios.plugins(s, opts));
      break;
    default:
      exitErr(`Unknown agent ios subcommand: ${sub}`);
  }
}

async function runRnCmd(sub: string | undefined, args: string[], s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent rn requires subcommand: arch|list|inject");
  switch (sub) {
    case "arch":
      printJson(await agent.rn.arch(s, opts));
      break;
    case "list":
      printJson(await agent.rn.list(s, opts));
      break;
    case "inject":
      if (!args[0] || !args[1] || !args[2]) exitErr("agent rn inject requires <handle> <arch> <script>");
      printJson(await agent.rn.inject(s, parseInt(args[0], 10), args[1], args[2], opts));
      break;
    default:
      exitErr(`Unknown agent rn subcommand: ${sub}`);
  }
}

async function runNativeCmd(sub: string | undefined, mod: string | undefined, name: string | undefined, s: SessionParams, opts: ClientOptions) {
  if (!sub) exitErr("agent native requires subcommand: list|hook|unhook");
  switch (sub) {
    case "list":
      printJson(await agent.native.list(s, opts));
      break;
    case "hook":
      if (!mod || !name) exitErr("agent native hook requires <module> <name>");
      await agent.native.hook(s, mod, name, opts);
      console.log("Native hook started");
      break;
    case "unhook":
      if (!mod || !name) exitErr("agent native unhook requires <module> <name>");
      await agent.native.unhook(s, mod, name, opts);
      console.log("Native hook stopped");
      break;
    default:
      exitErr(`Unknown agent native subcommand: ${sub}`);
  }
}

function printHelp() {
  console.log(`
igf - Grapefruit CLI

Usage: igf <command> [options]

Commands:
  version                     Show Frida & IGF versions

  device <subcommand>         Device management
    list                      List connected devices
    apps <device>             List apps on device
    ps <device>               List running processes
    info <device>             Device system parameters
    kill <device> <pid>       Kill a process

  log <subcommand>            Log management
    hooks <device> <id>       Query hook logs
    crypto <device> <id>      Query crypto logs
    syslog <device> <id>      Read syslog
    agent <device> <id>       Read agent log
    clear <device> <id>       Clear all logs

  history <subcommand>        Query history data
    http <device> <id>        HTTP history (Android)
    nsurl <device> <id>       NSURL history (iOS)
    jni <device> <id>         JNI history
    flutter <device> <id>     Flutter channel history
    xpc <device> <id>         XPC history (iOS)
    privacy <device> <id>     Privacy API logs
    hermes <device> <id>      Hermes JS captures

  agent <namespace> <subcommand>   Agent RPC (requires session)
    fs ls|cat|data|plist|preview|rm|cp|mv|mkdir|stat|access|roots|write
    app info|manifest|entitlements|urls|plist|process-info
    checksec all|main|single <name>
    class list|inspect|constants <name>
    classdump list|module|inheritance|inspect <name>   (iOS)
    hook list|status|start|stop|user-hooks <group>
    crypto status|available|start|stop <group>
    pin list|active|available|start|stop|snapshot <id>
    symbol modules|exports|imports|imports-grouped|strings|symbols|deps|sections|resolve|symbolicate
    thread list
    memory dump|scan|stop-scan|ranges|info <addr>
    lsof
    sqlite tables|dump|query <path> [table|sql]
    il2cpp available|info|assemblies|classes|search|detail|dump|gc-stats|gc-collect|gc-toggle|threads
    android activities|start-activity|services|start-service|stop-service
            receivers|send-broadcast|providers|provider-query
            keystore|keystore-info|keystore-cert|device-info|device-props
            resources|resource|webview
    ios keychain|keychain-remove|cookies|cookies-clear
        userdefaults|userdefaults-update|userdefaults-remove
        webviews|webviews-ui|webview-eval|webview-navigate
        jsc|jsc-dump|jsc-run
        geolocation|geolocation-dismiss|uidevice|open-url
        ui-dump|ui-highlight|ui-dismiss|plugins
    eval <code>
    rn arch|list|inject <handle> <arch> <script>
    native list|hook|unhook <module> <name>

Global Options:
  -H, --host <host>   Server host (default: localhost)
  -p, --port <port>   Server port (default: 31337)
  -h, --help          Show this help

Session Options (required for 'agent' commands):
  -d, --device <id>   Device ID
  --platform <name>   Platform: droid | fruity
  -b, --bundle <id>   Bundle ID (app mode)
  --pid <pid>         Process ID (daemon mode)
  -n, --name <name>   Process name (daemon mode)

Examples:
  igf device list
  igf device apps usb1234
  igf agent fs ls / -d usb1234 --platform droid -b com.example.app
  igf agent hook start ssl -d usb1234 --platform droid -b com.example.app
`);
}

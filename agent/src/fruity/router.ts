import * as checksec from "./modules/checksec.js";
import * as classdump from "./modules/classdump.js";
import * as cookies from "./modules/cookies.js";
import * as entitlements from "./modules/entitlements.js";
import * as fs from "./modules/fs.js";
import * as geolocation from "./modules/geolocation.js";
import * as info from "./modules/info.js";
import * as jsc from "./modules/jsc.js";
import * as keychain from "./modules/keychain.js";
import * as lsof from "./modules/lsof.js";
import * as symbol from "./modules/symbol.js";
import * as syslog from "./modules/syslog.js";
import * as ui from "./modules/ui.js";
import * as url from "./modules/url.js";
import * as userdefaults from "./modules/userdefaults.js";
import * as webview from "./modules/webview.js";

import * as objc from "./hooks/objc.js";
import * as hook from "./hooks/index.js";

import * as memory from "../common/memory.js";
import * as sqlite from "../common/sqlite.js";
import * as userscript from "../common/userscript.js";

if (!Process.findModuleByName("UIKit")) {
  console.warn("Not an UIKit App. Todo: disable some RPC");
}

export default {
  checksec,
  classdump,
  cookies,
  entitlements,
  fs,
  geolocation,
  hook,
  info,
  jsc,
  keychain,
  lsof,
  memory,
  objc,
  sqlite,
  symbol,
  syslog,
  ui,
  url,
  userscript,
  userdefaults,
  webview,
};

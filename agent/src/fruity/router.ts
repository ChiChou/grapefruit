import * as assetcatalog from "./modules/assetcatalog.js";
import * as checksec from "./modules/checksec.js";
import * as classdump from "./modules/classdump.js";
import * as cookies from "./modules/cookies.js";
import * as crypto from "./crypto/index.js";
import * as entitlements from "./modules/entitlements.js";
import * as fs from "./modules/fs.js";
import * as geolocation from "./modules/geolocation.js";
import * as hook from "./hooks/index.js";
import * as info from "./modules/info.js";
import * as jsc from "./modules/jsc.js";
import * as keychain from "./modules/keychain.js";
import * as lsof from "./modules/lsof.js";
import * as objc from "./hooks/objc.js";
import * as plugins from "./modules/plugins.js";
import * as rn from "./modules/rn.js";
import * as ui from "./modules/ui.js";
import * as uidevice from "./modules/uidevice.js";
import * as url from "./modules/url.js";
import * as userdefaults from "./modules/userdefaults.js";
import * as webview from "./modules/webview.js";

import * as taps from "./taps.js";

import * as memory from "@/common/memory.js";
import * as native from "@/common/hooks/native.js";
import * as sqlite from "@/common/sqlite.js";
import * as symbol from "@/common/symbol.js";
import * as script from "@/common/script.js";
import * as syslog from "@/common/syslog.js";
import * as threads from "@/common/threads.js";

if (!Process.findModuleByName("UIKit")) {
  console.warn("Not an UIKit App. Todo: disable some RPC");
}

export default {
  assetcatalog,
  checksec,
  classdump,
  cookies,
  crypto,
  entitlements,
  fs,
  geolocation,
  hook,
  info,
  jsc,
  keychain,
  lsof,
  memory,
  native,
  objc,
  plugins,
  rn,
  script,
  sqlite,
  symbol,
  syslog,
  taps,
  threads,
  ui,
  uidevice,
  url,
  userdefaults,
  webview,
};

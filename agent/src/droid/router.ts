import * as activities from "./modules/activities.js";
import * as apk from "./modules/apk.js";
import * as app from "./modules/app.js";
import * as checksec from "./modules/checksec/index.js";
import * as classes from "./modules/classes.js";
import * as device from "./modules/device.js";
import * as fs from "./modules/fs.js";
import * as hook from "./hooks/index.js";
import * as keystore from "./modules/keystore.js";
import * as lsof from "./modules/lsof.js";
import * as manifest from "./modules/manifest.js";
import * as provider from "./modules/provider.js";
import * as resources from "./modules/resources.js";
import * as rn from "./modules/rn.js";
import * as receivers from "./modules/receivers.js";
import * as services from "./modules/services.js";
import * as webview from "./modules/webview.js";

import * as pins from "./pins.js";

import * as il2cpp from "@/common/il2cpp.js";
import * as memory from "@/common/memory.js";
import * as native from "@/common/hooks/native.js";
import * as sqlite from "@/common/sqlite.js";
import * as symbol from "@/common/symbol.js";
import * as script from "@/common/script.js";
import * as syslog from "@/common/syslog.js";
import * as threads from "@/common/threads.js";

export default {
  activities,
  il2cpp,
  apk,
  app,
  checksec,
  classes,
  device,
  fs,
  hook,
  keystore,
  lsof,
  manifest,
  memory,
  native,
  provider,
  resources,
  receivers,
  rn,
  script,
  services,
  sqlite,
  symbol,
  syslog,
  pins,
  threads,
  webview,
};

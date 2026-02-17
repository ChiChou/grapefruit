import * as activities from "./modules/activities.js";
import * as app from "./modules/app.js";
import * as classes from "./modules/classes.js";
import * as device from "./modules/device.js";
import * as fs from "./modules/fs.js";
import * as provider from "./modules/provider.js";
import * as receivers from "./modules/receivers.js";
import * as services from "./modules/services.js";

import * as flutter from "./observers/flutter.js";

import * as memory from "@/common/memory.js";
import * as native from "@/common/hooks/native.js";
import * as sqlite from "@/common/sqlite.js";
import * as symbol from "@/common/symbol.js";
import * as script from "@/common/script.js";
import * as syslog from "@/common/syslog.js";

export default {
  activities,
  app,
  classes,
  device,
  flutter,
  fs,
  memory,
  native,
  provider,
  receivers,
  script,
  services,
  sqlite,
  symbol,
  syslog,
};

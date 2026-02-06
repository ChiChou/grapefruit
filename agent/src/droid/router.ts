import * as activities from "./modules/activities.js";
import * as device from "./modules/device.js";
import * as fs from "./modules/fs.js";
import * as pkg from "./modules/pkg.js";
import * as provider from "./modules/provider.js";
import * as receivers from "./modules/receivers.js";
import * as services from "./modules/services.js";

import * as memory from "@/common/memory.js";
import * as native from "@/common/hooks/native.js";
import * as sqlite from "@/common/sqlite.js";
import * as symbol from "@/common/symbol.js";
import * as syslog from "@/common/syslog.js";

export default {
  activities,
  device,
  fs,
  memory,
  native,
  pkg,
  provider,
  receivers,
  services,
  sqlite,
  symbol,
  syslog,
};

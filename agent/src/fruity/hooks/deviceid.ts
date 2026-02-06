import ObjC from "frida-objc-bridge";
import { BaseMessage } from "@/common/hooks/context.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "deviceid";
  original?: string;
  spoofed?: string;
}

function randomUUID(): string {
  return ObjC.classes.NSUUID.UUIDString;
}

// Generate fake IDs once per session
const FAKE_IDFV = randomUUID();
const FAKE_IDFA = randomUUID();

/**
 * Spoof device identifiers (IDFV, IDFA) with random UUIDs
 */
export function spoof() {
  if (!ObjC.available) return [];

  const hooks: InvocationListener[] = [];

  // Log the fake IDs at startup
  send({
    subject: "hook",
    category: "deviceid",
    symbol: "init",
    dir: "enter",
    line: `Spoofing IDFV=${FAKE_IDFV}, IDFA=${FAKE_IDFA}`,
    spoofed: `IDFV=${FAKE_IDFV}, IDFA=${FAKE_IDFA}`,
  } as Message);

  // Hook UIDevice identifierForVendor
  const UIDevice = ObjC.classes.UIDevice;
  if (UIDevice) {
    const idfvGetter = UIDevice["- identifierForVendor"];
    if (idfvGetter) {
      hooks.push(
        Interceptor.attach(idfvGetter.implementation, {
          onLeave(retval) {
            if (retval.isNull()) return;

            const original = new ObjC.Object(retval).UUIDString().toString();
            const fakeUUID =
              ObjC.classes.NSUUID.alloc().initWithUUIDString_(FAKE_IDFV);
            retval.replace(fakeUUID);

            send({
              subject: "hook",
              category: "deviceid",
              symbol: "-[UIDevice identifierForVendor]",
              dir: "leave",
              line: `identifierForVendor() → ${FAKE_IDFV} (was: ${original})`,
              original,
              spoofed: FAKE_IDFV,
            } as Message);
          },
        }),
      );
    }
  }

  // Hook ASIdentifierManager advertisingIdentifier (IDFA)
  const ASIdentifierManager = ObjC.classes.ASIdentifierManager;
  if (ASIdentifierManager) {
    const idfaGetter = ASIdentifierManager["- advertisingIdentifier"];
    if (idfaGetter) {
      hooks.push(
        Interceptor.attach(idfaGetter.implementation, {
          onLeave(retval) {
            if (retval.isNull()) return;

            const original = new ObjC.Object(retval).UUIDString().toString();
            const fakeUUID =
              ObjC.classes.NSUUID.alloc().initWithUUIDString_(FAKE_IDFA);
            retval.replace(fakeUUID);

            send({
              subject: "hook",
              category: "deviceid",
              symbol: "-[ASIdentifierManager advertisingIdentifier]",
              dir: "leave",
              line: `advertisingIdentifier() → ${FAKE_IDFA} (was: ${original})`,
              original,
              spoofed: FAKE_IDFA,
            } as Message);
          },
        }),
      );
    }
  }

  // Hook NSUUID UUIDString for any NSUUID that looks like a device ID
  // This catches cases where apps cache or transform the UUID
  const NSUUID = ObjC.classes.NSUUID;
  if (NSUUID) {
    const uuidStringGetter = NSUUID["- UUIDString"];
    if (uuidStringGetter) {
      // Track original IDFV/IDFA values to detect and replace them
      let originalIDFV: string | null = null;
      let originalIDFA: string | null = null;

      // Get the real values first
      try {
        if (UIDevice) {
          const device = UIDevice.currentDevice();
          const idfv = device.identifierForVendor();
          if (idfv) {
            originalIDFV = idfv.UUIDString().toString();
          }
        }
        if (ASIdentifierManager) {
          const manager = ASIdentifierManager.sharedManager();
          const idfa = manager.advertisingIdentifier();
          if (idfa) {
            originalIDFA = idfa.UUIDString().toString();
          }
        }
      } catch {
        // ignore errors getting original values
      }

      if (originalIDFV || originalIDFA) {
        hooks.push(
          Interceptor.attach(uuidStringGetter.implementation, {
            onLeave(retval) {
              if (retval.isNull()) return;

              const uuidStr = new ObjC.Object(retval).toString();

              // Replace if it matches original IDFV
              if (originalIDFV && uuidStr === originalIDFV) {
                const fakeStr =
                  ObjC.classes.NSString.stringWithString_(FAKE_IDFV);
                retval.replace(fakeStr);
              }
              // Replace if it matches original IDFA
              else if (originalIDFA && uuidStr === originalIDFA) {
                const fakeStr =
                  ObjC.classes.NSString.stringWithString_(FAKE_IDFA);
                retval.replace(fakeStr);
              }
            },
          }),
        );
      }
    }
  }

  return hooks;
}

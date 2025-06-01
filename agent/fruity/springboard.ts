import ObjC from "frida-objc-bridge";

if (!ObjC.available) throw new Error("This agent requires ObjC runtime");

const SBS = Module.load(
  "/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices",
);

function SBSApi(name: string) {
  const impl = SBS.findExportByName(name);
  if (!impl) throw new Error(`Api ${name} not found`);
  return impl;
}

function frontmost() {
  const SBSCopyFrontmostApplicationDisplayIdentifier = new NativeFunction(
    SBSApi("SBSCopyFrontmostApplicationDisplayIdentifier"),
    "pointer",
    [],
  );

  const identifier = SBSCopyFrontmostApplicationDisplayIdentifier();
  return new ObjC.Object(identifier).toString();
}

function locked() {
  const SBSSpringBoardServerPort = new NativeFunction(
    SBSApi("SBSSpringBoardServerPort"),
    "pointer",
    [],
  );

  const SBGetScreenLockStatus = new NativeFunction(
    SBSApi("SBGetScreenLockStatus"),
    "void",
    ["pointer", "pointer", "pointer"],
  );

  const pLocked = Memory.alloc(4);
  const pHasPasscode = Memory.alloc(4);
  const port = SBSSpringBoardServerPort();
  SBGetScreenLockStatus(port, pLocked, pHasPasscode);

  const locked = pLocked.readInt() !== 0;
  const hasPasscode = pHasPasscode.readInt() !== 0;

  console.log(
    `SpringBoard: screen locked ${locked}, has passcode? ${hasPasscode}`,
  );

  return locked;
}

async function pidOf(bundle: string): Promise<number> {
  return new Promise((resolve, reject) => {
    ObjC.schedule(ObjC.mainQueue, () => {
      const pid = ObjC.classes.FBSSystemService.sharedService().pidForApplication_(bundle);
      if (pid)
        resolve(pid);
      else
        reject(new Error(`No process found for bundle: ${bundle}`));
    });
  });
}

function open(bundle: string, url?: string) {
  const SBSLaunchApplicationWithIdentifierAndLaunchOptions = new NativeFunction(
    SBSApi("SBSLaunchApplicationWithIdentifierAndLaunchOptions"),
    "int",
    ["pointer", "pointer", "pointer", "bool"],
  );

  const SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions =
    new NativeFunction(
      SBSApi("SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions"),
      "int",
      ["pointer", "pointer", "pointer", "pointer", "bool"],
    );

  const bundleIdentifier = ObjC.classes.NSString.stringWithString_(bundle);
  if (typeof url === "string") {
    const nsurl = ObjC.classes.NSURL.URLWithString_(url);
    return (
      SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions(
        bundleIdentifier,
        nsurl,
        NULL,
        NULL,
        0,
      ) == 0
    );
  } else {
    return (
      SBSLaunchApplicationWithIdentifierAndLaunchOptions(
        bundleIdentifier,
        NULL,
        NULL,
        0,
      ) == 0
    );
  }
}

rpc.exports = {
  frontmost,
  locked,
  open,
  pidOf
};

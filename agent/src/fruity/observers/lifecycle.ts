import ObjC from "frida-objc-bridge";

let signalHandlerInstance: ObjC.Object;

function getSignalHandler(): ObjC.Object {
  if (!signalHandlerInstance) {
    const salt = Math.random().toString(36).slice(2);
    const name = `GrapefruitAppDelegate${salt}`;
    const MyAppDelegate = ObjC.registerProtocol({
      name: name + "Protocol",
      methods: {
        "- inactive": {
          retType: "void",
          argTypes: [],
        },
        "- background": {
          retType: "void",
          argTypes: [],
        },
        "- active": {
          retType: "void",
          argTypes: [],
        },
        "- foreground": {
          retType: "void",
          argTypes: [],
        },
      },
    });

    const subject = "lifecycle";
    const Clazz = ObjC.registerClass({
      name,
      super: ObjC.classes.NSObject,
      protocols: [MyAppDelegate, ObjC.protocols.NSObject],
      methods: {
        "- inactive": () => {
          send({ subject, event: "inactive" });
          console.warn("App will be inactive.");
        },
        "- background": () => {
          console.warn(
            "App is is now on the background. Grapefruit will be irresponsive.",
          );
          send({ subject, event: "background" });
        },
        "- active": () => {
          send({ subject, event: "active" });
          console.warn("App became active.");
        },
        "- foreground": () => {
          send({ subject, event: "foreground" });
          console.warn("App will enter foreground.");
        },
      },
    });

    signalHandlerInstance = Clazz.alloc().init();
  }

  return signalHandlerInstance as ObjC.Object;
}

function notificationCenter() {
  return ObjC.classes.NSNotificationCenter.defaultCenter();
}

export function init() {
  if (!ObjC.available || !ObjC.classes.NSNotificationCenter) {
    return;
  }

  const center = notificationCenter();
  const signalHandler = getSignalHandler();
  center.addObserver_selector_name_object_(
    signalHandler,
    ObjC.selector("inactive"),
    "UIApplicationWillResignActiveNotification",
    NULL,
  );
  center.addObserver_selector_name_object_(
    signalHandler,
    ObjC.selector("background"),
    "UIApplicationDidEnterBackgroundNotification",
    NULL,
  );
  center.addObserver_selector_name_object_(
    signalHandler,
    ObjC.selector("active"),
    "UIApplicationDidBecomeActiveNotification",
    NULL,
  );
  center.addObserver_selector_name_object_(
    signalHandler,
    ObjC.selector("foreground"),
    "UIApplicationWillEnterForegroundNotification",
    NULL,
  );
}

function dispose() {
  const center = notificationCenter();
  const signalHandler = getSignalHandler();

  center.removeObserver_name_object_(
    signalHandler,
    "UIApplicationWillResignActiveNotification",
    NULL,
  );
  center.removeObserver_name_object_(
    signalHandler,
    "UIApplicationDidEnterBackgroundNotification",
    NULL,
  );
  center.removeObserver_name_object_(
    signalHandler,
    "UIApplicationDidBecomeActiveNotification",
    NULL,
  );
  center.removeObserver_name_object_(
    signalHandler,
    "UIApplicationWillEnterForegroundNotification",
    NULL,
  );
}

Script.bindWeak(globalThis, dispose);

import ObjC from "frida-objc-bridge";

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
  },
});

const center = ObjC.classes.NSNotificationCenter.defaultCenter();

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
      send({ subject, event: "frozen" });
    },
  },
});

const signalHandler: ObjC.Object = Clazz.alloc().init();

export function init() {
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
}

function dispose() {
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
}

Script.bindWeak(globalThis, dispose);

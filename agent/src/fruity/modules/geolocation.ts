import ObjC from "frida-objc-bridge";

const CLLocationDegrees: NativeFunctionReturnType = "double";
const CLLocationCoordinate2D: NativeFunctionReturnType = [
  CLLocationDegrees,
  CLLocationDegrees,
];

let listeners: InvocationListener[] = [];
const hooked: Set<string> = new Set();

export function fake(lat: number, lng: number) {
  const pError = Memory.alloc(Process.pointerSize);
  ObjC.classes.NSBundle.bundleWithPath_(
    "/System/Library/Frameworks/CoreLocation.framework",
  ).loadAndReturnError_(pError);
  const err = pError.readPointer();
  if (!err.isNull()) {
    const error = new ObjC.Object(err);
    throw new Error(error.localizedDescription());
  }

  const CoreLocation = Process.getModuleByName("CoreLocation");
  const CLLocationCoordinate2DMake = new NativeFunction(
    CoreLocation.getExportByName("CLLocationCoordinate2DMake"),
    CLLocationCoordinate2D,
    ["double", "double"],
  );

  dismiss();

  const methods = [
    "- startUpdatingLocation",
    "- startUpdatingHeading", // heading is unavailable on macOS
    "- requestLocation",
  ];

  function fakeWithOrigin(location: ObjC.Object) {
    if (location.handle.isNull()) return location;

    const fake = CLLocationCoordinate2DMake(lat, lng);
    const newLocation = ObjC.classes.CLLocation.alloc()[
      "- initWithCoordinate:" +
        "altitude:" +
        "horizontalAccuracy:" +
        "verticalAccuracy:" +
        "course:" +
        "speed:" +
        "timestamp:"
    ](
      fake,
      location.altitude(),
      location.horizontalAccuracy(),
      location.verticalAccuracy(),
      location.course(),
      location.speed(),
      location.timestamp(),
    );

    return newLocation.autorelease();
  }

  const callbacks: {
    [sel: string]: (this: InvocationContext, args: InvocationArguments) => void;
  } = {
    "- locationManager:didUpdateToLocation:fromLocation:": function (args) {
      const to = new ObjC.Object(args[3]);
      const from = new ObjC.Object(args[4]);
      console.log(
        "- locationManager:didUpdateToLocation:fromLocation:",
        to,
        from,
      );

      args[3] = fakeWithOrigin(to);
      args[4] = fakeWithOrigin(from);
    },
    "- locationManager:didUpdateLocations:": function (args) {
      const array = new ObjC.Object(args[3]);
      const count = array.count().valueOf();
      const newArray =
        ObjC.classes.NSMutableArray.alloc().initWithCapacity_(count);
      for (let i = 0; i !== count; i++) {
        const location = array.objectAtIndex_(i);
        newArray.addObject_(fakeWithOrigin(location));
      }
      args[3] = newArray.autorelease();
    },
    "- locationManager:didUpdateHeading:": function (args) {
      console.log(
        "- locationManager:didUpdateHeading:",
        new ObjC.Object(args[3]),
      );
    },
  };

  function hookDelegate(delegate: ObjC.Object) {
    const className = delegate.$className;

    if (hooked.has(className)) return;
    const clazz = ObjC.classes[className];
    for (let sel in callbacks) {
      if (sel in clazz) {
        const l = Interceptor.attach(clazz[sel].implementation, {
          onEnter: callbacks[sel],
        });
        listeners.push(l);
      }
    }

    hooked.add(className);
  }

  const instances = ObjC.chooseSync(ObjC.classes.CLLocationManager);
  for (const mgr of instances) {
    const delegate = mgr.delegate();
    if (!delegate.handle.isNull()) hookDelegate(delegate);
    ObjC.schedule(ObjC.mainQueue, () => mgr.startUpdatingLocation());
  }

  for (const methodName of methods) {
    const method = ObjC.classes.CLLocationManager[
      methodName
    ] as ObjC.ObjectMethod;
    if (typeof method !== "function") continue;

    const l = Interceptor.attach(method.implementation, {
      onEnter(args) {
        const delegate = new ObjC.Object(args[0]).delegate();
        hookDelegate(delegate);
      },
    });
    listeners.push(l);
  }
}

export function dismiss() {
  listeners.forEach((l) => l.detach());
  listeners.length = 0;

  hooked.clear();
}

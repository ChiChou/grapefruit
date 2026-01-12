import ObjC from "frida-objc-bridge";
import { init as enableLifeCycleHook } from "./observers/lifecycle.js";
import { interfaces, invoke } from "./registry.js";

setImmediate(enableLifeCycleHook);

Process.setExceptionHandler((detail) => {
  console.error("Exception report: ");
  console.error(JSON.stringify(detail, null, 4));
  send({
    subject: "fatal",
    detail,
  });
  const { context } = detail;
  const pc = Instruction.parse(context.pc);
  console.warn(DebugSymbol.fromAddress(context.pc));
  console.error(pc.toString());
  console.error(Instruction.parse(pc.next).toString());
  console.error("Backtrace");
  console.error(
    Thread.backtrace(context, Backtracer.ACCURATE)
      .map((addr) => DebugSymbol.fromAddress(addr).toString())
      .join("\n"),
  );

  return false;
});

if (ObjC.available) {
  // disable autolock
  ObjC.schedule(ObjC.mainQueue, () => {
    try {
      ObjC.classes.UIApplication.sharedApplication().setIdleTimerDisabled_(
        ptr(1),
      );
    } finally {
    }
  });
}

rpc.exports = {
  invoke,
  interfaces,
};

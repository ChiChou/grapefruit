const SecTaskCopyValueForEntitlement = Module.findExportByName(null, 'SecTaskCopyValueForEntitlement');
const SecTaskCopyDebugDescription = new NativeFunction(DebugSymbol.getFunctionByName('SecTaskCopyDebugDescription'), 'pointer', ['pointer']);
const CFRelease = new NativeFunction(Module.findExportByName(null, 'CFRelease'), 'void', ['pointer']);
const CFStringGetCStringPtr = new NativeFunction(Module.findExportByName(null, 'CFStringGetCStringPtr'),
  'pointer', ['pointer', 'uint32']);
const kCFStringEncodingUTF8 = 0x08000100;
const expected = [
  'com.apple.security.get-task-allow',
  'com.apple.private.webinspector.allow-remote-inspection',
  'com.apple.private.webinspector.allow-carrier-remote-inspection',
  'com.apple.webinspector.allow'
];

Interceptor.attach(SecTaskCopyValueForEntitlement, {
  onEnter: function (args) {
    const p = CFStringGetCStringPtr(args[1], kCFStringEncodingUTF8);
    const ent = Memory.readUtf8String(p);
    if (expected.indexOf(ent) > -1) {
      this.shouldOverride = true;
      const description = SecTaskCopyDebugDescription(args[0])
      if (!description.isNull()) {
        const pDesc = CFStringGetCStringPtr(description, kCFStringEncodingUTF8);
        console.log('enable inspector for', Memory.readUtf8String(pDesc));
        CFRelease(description);
      }
    }
  },
  onLeave: function (retVal) {
    if (!this.shouldOverride) return;
    if (!retVal.isNull()) CFRelease(retVal);
    retVal.replace(ObjC.classes.NSNumber.numberWithBool_(1));
  }
});

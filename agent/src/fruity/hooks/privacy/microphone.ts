import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  // AVAudioRecorder record
  try {
    const cls = ObjC.classes.AVAudioRecorder;
    if (cls) {
      const m = cls["- record"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("microphone", "-[AVAudioRecorder record]", "enter",
                "AVAudioRecorder.record()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // AVCaptureDevice requestAccessForMediaType: (audio)
  try {
    const cls = ObjC.classes.AVCaptureDevice;
    if (cls) {
      const m = cls["+ requestAccessForMediaType:completionHandler:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter(args) {
              const mediaType = new ObjC.Object(args[2]).toString();
              if (mediaType === "soun") {
                send(privacyMsg("microphone",
                  "+[AVCaptureDevice requestAccessForMediaType:completionHandler:]",
                  "enter",
                  `requestAccessForMediaType: audio`,
                  bt(this.context),
                  { mediaType }));
              }
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // AVAudioEngine startAndReturnError:
  try {
    const cls = ObjC.classes.AVAudioEngine;
    if (cls) {
      const m = cls["- startAndReturnError:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("microphone", "-[AVAudioEngine startAndReturnError:]", "enter",
                "AVAudioEngine.start()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // AudioOutputUnitStart (C function)
  try {
    const mod = Process.findModuleByName("AudioToolbox");
    const addr = mod?.findExportByName("AudioOutputUnitStart");
    if (addr) {
      hooks.push(
        Interceptor.attach(addr, {
          onEnter() {
            send(privacyMsg("microphone", "AudioOutputUnitStart", "enter",
              "AudioOutputUnitStart()", bt(this.context)));
          },
        }),
      );
    }
  } catch { /* symbol unavailable */ }

  return hooks;
}

import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "@/common/hooks/privacy.js";

export function hook(): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  // AVCaptureSession startRunning
  try {
    const cls = ObjC.classes.AVCaptureSession;
    if (cls) {
      const m = cls["- startRunning"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("camera", "-[AVCaptureSession startRunning]", "enter",
                "AVCaptureSession.startRunning()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // AVCaptureDevice requestAccessForMediaType: (video)
  try {
    const cls = ObjC.classes.AVCaptureDevice;
    if (cls) {
      const m = cls["+ requestAccessForMediaType:completionHandler:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter(args) {
              const mediaType = new ObjC.Object(args[2]).toString();
              if (mediaType === "vide") {
                send(privacyMsg("camera",
                  "+[AVCaptureDevice requestAccessForMediaType:completionHandler:]",
                  "enter",
                  `requestAccessForMediaType: video`,
                  bt(this.context),
                  { mediaType }));
              }
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // UIImagePickerController takePicture
  try {
    const cls = ObjC.classes.UIImagePickerController;
    if (cls) {
      const m = cls["- takePicture"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("camera", "-[UIImagePickerController takePicture]", "enter",
                "UIImagePickerController.takePicture()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // UIImagePickerController startVideoCapture
  try {
    const cls = ObjC.classes.UIImagePickerController;
    if (cls) {
      const m = cls["- startVideoCapture"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("camera", "-[UIImagePickerController startVideoCapture]", "enter",
                "UIImagePickerController.startVideoCapture()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  return hooks;
}

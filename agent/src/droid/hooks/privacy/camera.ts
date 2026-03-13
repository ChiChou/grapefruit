import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // Camera.open
  try {
    const Camera = Java.use("android.hardware.Camera");
    hooks.push(
      hook(Camera.open.overload("int"), (original, self, args) => {
        const cameraId = args[0] as number;
        send(
          privacyMsg(
            "camera",
            "Camera.open",
            "enter",
            `Camera.open(${cameraId})`,
            bt(),
            { cameraId },
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* class unavailable */
  }

  // CameraManager.openCamera
  try {
    const CameraManager = Java.use("android.hardware.camera2.CameraManager");
    hooks.push(
      hook(
        CameraManager.openCamera.overload(
          "java.lang.String",
          "android.hardware.camera2.CameraDevice$StateCallback",
          "android.os.Handler",
        ),
        (original, self, args) => {
          const cameraId = (args[0] as Java.Wrapper)?.toString() ?? "unknown";
          send(
            privacyMsg(
              "camera",
              "CameraManager.openCamera",
              "enter",
              `CameraManager.openCamera("${cameraId}")`,
              bt(),
              { cameraId },
            ),
          );
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  // ImageCapture.takePicture
  try {
    const ImageCapture = Java.use("androidx.camera.core.ImageCapture");
    hooks.push(
      hook(
        ImageCapture.takePicture.overload(
          "androidx.camera.core.ImageCapture$OutputFileOptions",
          "java.util.concurrent.Executor",
          "androidx.camera.core.ImageCapture$OnImageSavedCallback",
        ),
        (original, self, args) => {
          send(
            privacyMsg(
              "camera",
              "ImageCapture.takePicture",
              "enter",
              "ImageCapture.takePicture()",
              bt(),
            ),
          );
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  return hooks;
}

import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "@/common/hooks/privacy.js";

export function hook(): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  // PHPhotoLibrary requestAuthorization:
  try {
    const cls = ObjC.classes.PHPhotoLibrary;
    if (cls) {
      const m = cls["+ requestAuthorization:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("photos", "+[PHPhotoLibrary requestAuthorization:]", "enter",
                "PHPhotoLibrary.requestAuthorization()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // PHPhotoLibrary requestAuthorizationForAccessLevel:handler:
  try {
    const cls = ObjC.classes.PHPhotoLibrary;
    if (cls) {
      const m = cls["+ requestAuthorizationForAccessLevel:handler:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter(args) {
              const level = args[2].toInt32();
              const levelName = level === 1 ? "addOnly" : level === 2 ? "readWrite" : String(level);
              send(privacyMsg("photos",
                "+[PHPhotoLibrary requestAuthorizationForAccessLevel:handler:]",
                "enter",
                `requestAuthorizationForAccessLevel: ${levelName}`,
                bt(this.context),
                { accessLevel: levelName }));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // PHAsset fetchAssetsWithOptions:
  try {
    const cls = ObjC.classes.PHAsset;
    if (cls) {
      const m = cls["+ fetchAssetsWithOptions:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("photos", "+[PHAsset fetchAssetsWithOptions:]", "enter",
                "PHAsset.fetchAssetsWithOptions()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // PHAsset fetchAssetsWithMediaType:options:
  try {
    const cls = ObjC.classes.PHAsset;
    if (cls) {
      const m = cls["+ fetchAssetsWithMediaType:options:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter(args) {
              const mediaType = args[2].toInt32();
              const typeName = mediaType === 1 ? "image" : mediaType === 2 ? "video" : mediaType === 3 ? "audio" : String(mediaType);
              send(privacyMsg("photos",
                "+[PHAsset fetchAssetsWithMediaType:options:]",
                "enter",
                `fetchAssetsWithMediaType: ${typeName}`,
                bt(this.context),
                { mediaType: typeName }));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  return hooks;
}

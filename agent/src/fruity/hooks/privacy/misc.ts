import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg, type PrivacyCategory } from "@/common/hooks/privacy.js";

function hookSimple(
  cls: ObjC.Object,
  sel: string,
  category: PrivacyCategory,
  line: string,
  hooks: InvocationListener[],
) {
  try {
    const m = cls[sel];
    if (m) {
      const symbol = `${sel.startsWith("+") ? "" : "-"}[${cls.$className} ${sel.replace(/^[+-]\s*/, "")}]`;
      hooks.push(
        Interceptor.attach(m.implementation, {
          onEnter() {
            send(privacyMsg(category, symbol, "enter", line, bt(this.context)));
          },
        }),
      );
    }
  } catch {
    /* method unavailable */
  }
}

export function hook(): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  // Focus Status
  try {
    const cls = ObjC.classes.INFocusStatusCenter;
    if (cls) {
      hookSimple(
        cls,
        "- focusStatus",
        "focus_status",
        "INFocusStatusCenter.focusStatus",
        hooks,
      );
      hookSimple(
        cls,
        "- requestAuthorizationWithCompletion:",
        "focus_status",
        "INFocusStatusCenter.requestAuthorization()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  // Game Center
  try {
    const cls = ObjC.classes.GKLocalPlayer;
    if (cls) {
      hookSimple(
        cls,
        "- loadFriendsWithCompletionHandler:",
        "game_center",
        "GKLocalPlayer.loadFriends()",
        hooks,
      );
      hookSimple(
        cls,
        "- loadPhotoForSize:withCompletionHandler:",
        "game_center",
        "GKLocalPlayer.loadPhoto()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  // HomeKit
  try {
    const cls = ObjC.classes.HMHomeManager;
    if (cls) {
      hookSimple(cls, "- homes", "homekit", "HMHomeManager.homes", hooks);
    }
  } catch {
    /* class unavailable */
  }

  try {
    const cls = ObjC.classes.HMCharacteristic;
    if (cls) {
      hookSimple(
        cls,
        "- readValueWithCompletionHandler:",
        "homekit",
        "HMCharacteristic.readValue()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  try {
    const cls = ObjC.classes.HMCameraStreamControl;
    if (cls) {
      hookSimple(
        cls,
        "- startStream",
        "homekit",
        "HMCameraStreamControl.startStream()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  // SafetyKit
  try {
    const cls = ObjC.classes.SACrashDetectionManager;
    if (cls) {
      hookSimple(
        cls,
        "- requestAuthorizationWithCompletionHandler:",
        "safetykit",
        "SACrashDetectionManager.requestAuthorization()",
        hooks,
      );
      hookSimple(
        cls,
        "- setDelegate:",
        "safetykit",
        "SACrashDetectionManager.setDelegate()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  try {
    const cls = ObjC.classes.SAFallDetectionManager;
    if (cls) {
      hookSimple(
        cls,
        "- requestAuthorizationWithCompletionHandler:",
        "safetykit",
        "SAFallDetectionManager.requestAuthorization()",
        hooks,
      );
      hookSimple(
        cls,
        "- setDelegate:",
        "safetykit",
        "SAFallDetectionManager.setDelegate()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  // SensorKit
  try {
    const cls = ObjC.classes.SRSensorReader;
    if (cls) {
      hookSimple(
        cls,
        "- requestAuthorizationWithSensors:completion:",
        "sensorkit",
        "SRSensorReader.requestAuthorization()",
        hooks,
      );
      hookSimple(
        cls,
        "- startRecording",
        "sensorkit",
        "SRSensorReader.startRecording()",
        hooks,
      );
      hookSimple(
        cls,
        "- fetchDevices",
        "sensorkit",
        "SRSensorReader.fetchDevices()",
        hooks,
      );
    }
  } catch {
    /* class unavailable */
  }

  return hooks;
}

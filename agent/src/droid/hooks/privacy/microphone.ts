import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // AudioRecord.startRecording
  try {
    const AudioRecord = Java.use("android.media.AudioRecord");
    hooks.push(
      hook(AudioRecord.startRecording.overload(), (original, self, args) => {
        send(
          privacyMsg(
            "microphone",
            "AudioRecord.startRecording",
            "enter",
            "AudioRecord.startRecording()",
            bt(),
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* class unavailable */
  }

  // MediaRecorder.start
  try {
    const MediaRecorder = Java.use("android.media.MediaRecorder");
    hooks.push(
      hook(MediaRecorder.start.overload(), (original, self, args) => {
        send(
          privacyMsg(
            "microphone",
            "MediaRecorder.start",
            "enter",
            "MediaRecorder.start()",
            bt(),
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* class unavailable */
  }

  // MediaRecorder.prepare
  try {
    const MediaRecorder = Java.use("android.media.MediaRecorder");
    hooks.push(
      hook(MediaRecorder.prepare.overload(), (original, self, args) => {
        send(
          privacyMsg(
            "microphone",
            "MediaRecorder.prepare",
            "enter",
            "MediaRecorder.prepare()",
            bt(),
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* class unavailable */
  }

  return hooks;
}

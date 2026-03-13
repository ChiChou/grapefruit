import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // ContentResolver.query (filter for MediaStore URIs)
  try {
    const ContentResolver = Java.use("android.content.ContentResolver");
    hooks.push(
      hook(
        ContentResolver.query.overload(
          "android.net.Uri",
          "[Ljava.lang.String;",
          "java.lang.String",
          "[Ljava.lang.String;",
          "java.lang.String",
        ),
        (original, self, args) => {
          const uri = (args[0] as Java.Wrapper)?.toString() ?? "";
          if (uri.includes("media/") || uri.includes("MediaStore")) {
            send(
              privacyMsg(
                "photos",
                "ContentResolver.query",
                "enter",
                `ContentResolver.query(${uri})`,
                bt(),
                { uri },
              ),
            );
          }
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  // Activity.startActivityForResult (filter for image/video pick intents)
  try {
    const Activity = Java.use("android.app.Activity");
    hooks.push(
      hook(
        Activity.startActivityForResult.overload(
          "android.content.Intent",
          "int",
        ),
        (original, self, args) => {
          const intent = args[0] as Java.Wrapper;
          try {
            const action = intent.getAction()?.toString() ?? "";
            const type = intent.getType()?.toString() ?? "";
            if (
              (action === "android.intent.action.PICK" ||
                action === "android.intent.action.GET_CONTENT") &&
              (type.startsWith("image/") || type.startsWith("video/"))
            ) {
              send(
                privacyMsg(
                  "photos",
                  "Activity.startActivityForResult",
                  "enter",
                  `startActivityForResult(${action}, ${type})`,
                  bt(),
                  { action, type },
                ),
              );
            }
          } catch {
            /* ignore */
          }
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  return hooks;
}

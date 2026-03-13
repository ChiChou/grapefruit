import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

function hookGameCenter(hooks: InvocationListener[]) {
  try {
    const PlayersClient = Java.use(
      "com.google.android.gms.games.PlayersClient",
    );

    try {
      hooks.push(
        hook(
          PlayersClient.getCurrentPlayer.overload(),
          (original, self, args) => {
            send(
              privacyMsg(
                "game_center",
                "PlayersClient.getCurrentPlayer",
                "enter",
                "PlayersClient.getCurrentPlayer()",
                bt(),
              ),
            );
            return original.call(self, ...args);
          },
        ),
      );
    } catch {
      /* overload unavailable */
    }

    try {
      hooks.push(
        hook(
          PlayersClient.loadFriends.overload("int", "boolean"),
          (original, self, args) => {
            send(
              privacyMsg(
                "game_center",
                "PlayersClient.loadFriends",
                "enter",
                "PlayersClient.loadFriends()",
                bt(),
              ),
            );
            return original.call(self, ...args);
          },
        ),
      );
    } catch {
      /* overload unavailable */
    }
  } catch {
    /* GMS unavailable */
  }
}

function hookHome(hooks: InvocationListener[]) {
  try {
    const HomeClient = Java.use("com.google.android.gms.home.HomeClient");

    try {
      hooks.push(
        hook(HomeClient.structures.overload(), (original, self, args) => {
          send(
            privacyMsg(
              "homekit",
              "HomeClient.structures",
              "enter",
              "HomeClient.structures()",
              bt(),
            ),
          );
          return original.call(self, ...args);
        }),
      );
    } catch {
      /* overload unavailable */
    }

    try {
      hooks.push(
        hook(HomeClient.devices.overload(), (original, self, args) => {
          send(
            privacyMsg(
              "homekit",
              "HomeClient.devices",
              "enter",
              "HomeClient.devices()",
              bt(),
            ),
          );
          return original.call(self, ...args);
        }),
      );
    } catch {
      /* overload unavailable */
    }
  } catch {
    /* GMS unavailable */
  }
}

function hookActivityRecognition(hooks: InvocationListener[]) {
  try {
    const ARC = Java.use(
      "com.google.android.gms.location.ActivityRecognitionClient",
    );

    try {
      hooks.push(
        hook(
          ARC.requestActivityUpdates.overload(
            "long",
            "android.app.PendingIntent",
          ),
          (original, self, args) => {
            send(
              privacyMsg(
                "activity_recognition",
                "ActivityRecognitionClient.requestActivityUpdates",
                "enter",
                "ActivityRecognitionClient.requestActivityUpdates()",
                bt(),
              ),
            );
            return original.call(self, ...args);
          },
        ),
      );
    } catch {
      /* overload unavailable */
    }

    try {
      hooks.push(
        hook(
          ARC.requestActivityTransitionUpdates.overload(
            "com.google.android.gms.location.ActivityTransitionRequest",
            "android.app.PendingIntent",
          ),
          (original, self, args) => {
            send(
              privacyMsg(
                "activity_recognition",
                "ActivityRecognitionClient.requestActivityTransitionUpdates",
                "enter",
                "ActivityRecognitionClient.requestActivityTransitionUpdates()",
                bt(),
              ),
            );
            return original.call(self, ...args);
          },
        ),
      );
    } catch {
      /* overload unavailable */
    }
  } catch {
    /* GMS unavailable */
  }
}

function hookUsageStats(hooks: InvocationListener[]) {
  try {
    const UsageStatsManager = Java.use("android.app.usage.UsageStatsManager");

    try {
      hooks.push(
        hook(
          UsageStatsManager.queryUsageStats.overload("int", "long", "long"),
          (original, self, args) => {
            send(
              privacyMsg(
                "usage_stats",
                "UsageStatsManager.queryUsageStats",
                "enter",
                "UsageStatsManager.queryUsageStats()",
                bt(),
              ),
            );
            return original.call(self, ...args);
          },
        ),
      );
    } catch {
      /* overload unavailable */
    }

    try {
      hooks.push(
        hook(
          UsageStatsManager.queryEvents.overload("long", "long"),
          (original, self, args) => {
            send(
              privacyMsg(
                "usage_stats",
                "UsageStatsManager.queryEvents",
                "enter",
                "UsageStatsManager.queryEvents()",
                bt(),
              ),
            );
            return original.call(self, ...args);
          },
        ),
      );
    } catch {
      /* overload unavailable */
    }
  } catch {
    /* class unavailable */
  }
}

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];
  hookGameCenter(hooks);
  hookHome(hooks);
  hookActivityRecognition(hooks);
  hookUsageStats(hooks);
  return hooks;
}

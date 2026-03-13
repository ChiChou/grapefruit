import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // HealthConnectClient
  try {
    const HCC = Java.use("androidx.health.connect.client.HealthConnectClient");
    try {
      hooks.push(
        hook(
          HCC.readRecords.overload(
            "androidx.health.connect.client.request.ReadRecordsRequest",
          ),
          (original, self, args) => {
            send(
              privacyMsg(
                "health",
                "HealthConnectClient.readRecords",
                "enter",
                "HealthConnectClient.readRecords()",
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
          HCC.insertRecords.overload("java.util.List"),
          (original, self, args) => {
            send(
              privacyMsg(
                "health",
                "HealthConnectClient.insertRecords",
                "enter",
                "HealthConnectClient.insertRecords()",
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

  // Google Fit HistoryClient
  try {
    const HistoryClient = Java.use(
      "com.google.android.gms.fitness.HistoryClient",
    );
    hooks.push(
      hook(
        HistoryClient.readData.overload(
          "com.google.android.gms.fitness.request.DataReadRequest",
        ),
        (original, self, args) => {
          send(
            privacyMsg(
              "health",
              "HistoryClient.readData",
              "enter",
              "GoogleFit.HistoryClient.readData()",
              bt(),
            ),
          );
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* GMS unavailable */
  }

  return hooks;
}

import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // LocationManager methods
  try {
    const LocationManager = Java.use("android.location.LocationManager");

    try {
      hooks.push(
        hook(
          LocationManager.requestLocationUpdates.overload(
            "java.lang.String",
            "long",
            "float",
            "android.location.LocationListener",
          ),
          (original, self, args) => {
            const provider = (args[0] as Java.Wrapper)?.toString() ?? "unknown";
            send(
              privacyMsg(
                "location",
                "LocationManager.requestLocationUpdates",
                "enter",
                `requestLocationUpdates(${provider})`,
                bt(),
                { provider },
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
          LocationManager.getLastKnownLocation.overload("java.lang.String"),
          (original, self, args) => {
            const provider = (args[0] as Java.Wrapper)?.toString() ?? "unknown";
            send(
              privacyMsg(
                "location",
                "LocationManager.getLastKnownLocation",
                "enter",
                `getLastKnownLocation(${provider})`,
                bt(),
                { provider },
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

  // FusedLocationProviderClient (GMS)
  try {
    const FusedClient = Java.use(
      "com.google.android.gms.location.FusedLocationProviderClient",
    );

    try {
      hooks.push(
        hook(FusedClient.getLastLocation.overload(), (original, self, args) => {
          send(
            privacyMsg(
              "location",
              "FusedLocationProviderClient.getLastLocation",
              "enter",
              "FusedLocationProviderClient.getLastLocation()",
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
        hook(
          FusedClient.requestLocationUpdates.overload(
            "com.google.android.gms.location.LocationRequest",
            "com.google.android.gms.location.LocationCallback",
            "android.os.Looper",
          ),
          (original, self, args) => {
            send(
              privacyMsg(
                "location",
                "FusedLocationProviderClient.requestLocationUpdates",
                "enter",
                "FusedLocationProviderClient.requestLocationUpdates()",
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
          FusedClient.getCurrentLocation.overload(
            "int",
            "com.google.android.gms.tasks.CancellationToken",
          ),
          (original, self, args) => {
            send(
              privacyMsg(
                "location",
                "FusedLocationProviderClient.getCurrentLocation",
                "enter",
                "FusedLocationProviderClient.getCurrentLocation()",
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

  return hooks;
}

import Java from "frida-java-bridge";

import { patch as createPatch, backtrace } from "@/common/hooks/java.js";
import { privacyMsg, type PrivacyCategory } from "@/common/hooks/privacy.js";

const restores: Array<() => void> = [];
let running = false;

const patch = createPatch(restores);

function msg(
  category: PrivacyCategory,
  symbol: string,
  line: string,
  extra?: Record<string, unknown>,
) {
  send(privacyMsg(category, symbol, "enter", line, backtrace(), extra));
}

function hookMicrophone() {
  // AudioRecord.startRecording
  try {
    const AudioRecord = Java.use("android.media.AudioRecord");
    patch(AudioRecord.startRecording.overload(), (original, self, args) => {
      msg("microphone", "AudioRecord.startRecording", "AudioRecord.startRecording()");
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }

  // MediaRecorder.start
  try {
    const MediaRecorder = Java.use("android.media.MediaRecorder");
    patch(MediaRecorder.start.overload(), (original, self, args) => {
      msg("microphone", "MediaRecorder.start", "MediaRecorder.start()");
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }

  // MediaRecorder.prepare
  try {
    const MediaRecorder = Java.use("android.media.MediaRecorder");
    patch(MediaRecorder.prepare.overload(), (original, self, args) => {
      msg("microphone", "MediaRecorder.prepare", "MediaRecorder.prepare()");
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }
}

function hookCamera() {
  // Camera.open
  try {
    const Camera = Java.use("android.hardware.Camera");
    patch(Camera.open.overload("int"), (original, self, args) => {
      const cameraId = args[0] as number;
      msg("camera", "Camera.open", `Camera.open(${cameraId})`, { cameraId });
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }

  // CameraManager.openCamera
  try {
    const CameraManager = Java.use("android.hardware.camera2.CameraManager");
    patch(
      CameraManager.openCamera.overload(
        "java.lang.String",
        "android.hardware.camera2.CameraDevice$StateCallback",
        "android.os.Handler",
      ),
      (original, self, args) => {
        const cameraId = (args[0] as Java.Wrapper)?.toString() ?? "unknown";
        msg("camera", "CameraManager.openCamera", `CameraManager.openCamera("${cameraId}")`, { cameraId });
        return original.call(self, ...args);
      },
    );
  } catch { /* class unavailable */ }

  // ImageCapture.takePicture
  try {
    const ImageCapture = Java.use("androidx.camera.core.ImageCapture");
    patch(
      ImageCapture.takePicture.overload(
        "androidx.camera.core.ImageCapture$OutputFileOptions",
        "java.util.concurrent.Executor",
        "androidx.camera.core.ImageCapture$OnImageSavedCallback",
      ),
      (original, self, args) => {
        msg("camera", "ImageCapture.takePicture", "ImageCapture.takePicture()");
        return original.call(self, ...args);
      },
    );
  } catch { /* class unavailable */ }
}

function hookPhotos() {
  // ContentResolver.query (filter for MediaStore URIs)
  try {
    const ContentResolver = Java.use("android.content.ContentResolver");
    patch(
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
          msg("photos", "ContentResolver.query", `ContentResolver.query(${uri})`, { uri });
        }
        return original.call(self, ...args);
      },
    );
  } catch { /* class unavailable */ }

  // Activity.startActivityForResult (filter for image/video pick intents)
  try {
    const Activity = Java.use("android.app.Activity");
    patch(
      Activity.startActivityForResult.overload("android.content.Intent", "int"),
      (original, self, args) => {
        const intent = args[0] as Java.Wrapper;
        try {
          const action = intent.getAction()?.toString() ?? "";
          const type = intent.getType()?.toString() ?? "";
          if (
            (action === "android.intent.action.PICK" || action === "android.intent.action.GET_CONTENT") &&
            (type.startsWith("image/") || type.startsWith("video/"))
          ) {
            msg("photos", "Activity.startActivityForResult",
              `startActivityForResult(${action}, ${type})`, { action, type });
          }
        } catch { /* ignore */ }
        return original.call(self, ...args);
      },
    );
  } catch { /* class unavailable */ }
}

function hookSensors() {
  try {
    const SensorManager = Java.use("android.hardware.SensorManager");
    patch(
      SensorManager.registerListener.overload(
        "android.hardware.SensorEventListener",
        "android.hardware.Sensor",
        "int",
      ),
      (original, self, args) => {
        let sensorType = "unknown";
        try {
          const sensor = args[1] as Java.Wrapper;
          sensorType = String(sensor.getType());
        } catch { /* ignore */ }
        msg("motion_sensors", "SensorManager.registerListener",
          `SensorManager.registerListener(type=${sensorType})`, { sensorType });
        return original.call(self, ...args);
      },
    );
  } catch { /* class unavailable */ }
}

function hookBluetooth() {
  // BluetoothAdapter.startDiscovery
  try {
    const BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
    patch(BluetoothAdapter.startDiscovery.overload(), (original, self, args) => {
      msg("bluetooth", "BluetoothAdapter.startDiscovery", "BluetoothAdapter.startDiscovery()");
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }

  // BluetoothAdapter.getBondedDevices
  try {
    const BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
    patch(BluetoothAdapter.getBondedDevices.overload(), (original, self, args) => {
      msg("bluetooth", "BluetoothAdapter.getBondedDevices", "BluetoothAdapter.getBondedDevices()");
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }

  // BluetoothLeScanner.startScan
  try {
    const BluetoothLeScanner = Java.use("android.bluetooth.le.BluetoothLeScanner");
    patch(
      BluetoothLeScanner.startScan.overload("android.bluetooth.le.ScanCallback"),
      (original, self, args) => {
        msg("bluetooth", "BluetoothLeScanner.startScan", "BluetoothLeScanner.startScan()");
        return original.call(self, ...args);
      },
    );
  } catch { /* class unavailable */ }
}

function hookWifi() {
  const WifiManager = Java.use("android.net.wifi.WifiManager");

  // startScan
  try {
    patch(WifiManager.startScan.overload(), (original, self, args) => {
      msg("wifi", "WifiManager.startScan", "WifiManager.startScan()");
      return original.call(self, ...args);
    });
  } catch { /* method unavailable */ }

  // getScanResults
  try {
    patch(WifiManager.getScanResults.overload(), (original, self, args) => {
      msg("wifi", "WifiManager.getScanResults", "WifiManager.getScanResults()");
      return original.call(self, ...args);
    });
  } catch { /* method unavailable */ }

  // getConnectionInfo
  try {
    patch(WifiManager.getConnectionInfo.overload(), (original, self, args) => {
      msg("wifi", "WifiManager.getConnectionInfo", "WifiManager.getConnectionInfo()");
      return original.call(self, ...args);
    });
  } catch { /* method unavailable */ }

  // ConnectivityManager.getActiveNetworkInfo
  try {
    const ConnectivityManager = Java.use("android.net.ConnectivityManager");
    patch(ConnectivityManager.getActiveNetworkInfo.overload(), (original, self, args) => {
      msg("wifi", "ConnectivityManager.getActiveNetworkInfo", "ConnectivityManager.getActiveNetworkInfo()");
      return original.call(self, ...args);
    });
  } catch { /* class unavailable */ }
}

function hookLocation() {
  // LocationManager methods
  try {
    const LocationManager = Java.use("android.location.LocationManager");

    try {
      patch(
        LocationManager.requestLocationUpdates.overload(
          "java.lang.String", "long", "float", "android.location.LocationListener",
        ),
        (original, self, args) => {
          const provider = (args[0] as Java.Wrapper)?.toString() ?? "unknown";
          msg("location", "LocationManager.requestLocationUpdates",
            `requestLocationUpdates(${provider})`, { provider });
          return original.call(self, ...args);
        },
      );
    } catch { /* overload unavailable */ }

    try {
      patch(LocationManager.getLastKnownLocation.overload("java.lang.String"), (original, self, args) => {
        const provider = (args[0] as Java.Wrapper)?.toString() ?? "unknown";
        msg("location", "LocationManager.getLastKnownLocation",
          `getLastKnownLocation(${provider})`, { provider });
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }
  } catch { /* class unavailable */ }

  // FusedLocationProviderClient (GMS)
  try {
    const FusedClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");

    try {
      patch(FusedClient.getLastLocation.overload(), (original, self, args) => {
        msg("location", "FusedLocationProviderClient.getLastLocation",
          "FusedLocationProviderClient.getLastLocation()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }

    try {
      patch(
        FusedClient.requestLocationUpdates.overload(
          "com.google.android.gms.location.LocationRequest",
          "com.google.android.gms.location.LocationCallback",
          "android.os.Looper",
        ),
        (original, self, args) => {
          msg("location", "FusedLocationProviderClient.requestLocationUpdates",
            "FusedLocationProviderClient.requestLocationUpdates()");
          return original.call(self, ...args);
        },
      );
    } catch { /* overload unavailable */ }

    try {
      patch(FusedClient.getCurrentLocation.overload("int", "com.google.android.gms.tasks.CancellationToken"), (original, self, args) => {
        msg("location", "FusedLocationProviderClient.getCurrentLocation",
          "FusedLocationProviderClient.getCurrentLocation()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }
  } catch { /* GMS unavailable */ }
}

function hookHealth() {
  // HealthConnectClient
  try {
    const HCC = Java.use("androidx.health.connect.client.HealthConnectClient");
    try {
      patch(HCC.readRecords.overload("androidx.health.connect.client.request.ReadRecordsRequest"), (original, self, args) => {
        msg("health", "HealthConnectClient.readRecords", "HealthConnectClient.readRecords()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }

    try {
      patch(HCC.insertRecords.overload("java.util.List"), (original, self, args) => {
        msg("health", "HealthConnectClient.insertRecords", "HealthConnectClient.insertRecords()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }
  } catch { /* class unavailable */ }

  // Google Fit HistoryClient
  try {
    const HistoryClient = Java.use("com.google.android.gms.fitness.HistoryClient");
    patch(HistoryClient.readData.overload("com.google.android.gms.fitness.request.DataReadRequest"), (original, self, args) => {
      msg("health", "HistoryClient.readData", "GoogleFit.HistoryClient.readData()");
      return original.call(self, ...args);
    });
  } catch { /* GMS unavailable */ }
}

function hookGameCenter() {
  try {
    const PlayersClient = Java.use("com.google.android.gms.games.PlayersClient");

    try {
      patch(PlayersClient.getCurrentPlayer.overload(), (original, self, args) => {
        msg("game_center", "PlayersClient.getCurrentPlayer", "PlayersClient.getCurrentPlayer()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }

    try {
      patch(PlayersClient.loadFriends.overload("int", "boolean"), (original, self, args) => {
        msg("game_center", "PlayersClient.loadFriends", "PlayersClient.loadFriends()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }
  } catch { /* GMS unavailable */ }
}

function hookHome() {
  try {
    const HomeClient = Java.use("com.google.android.gms.home.HomeClient");

    try {
      patch(HomeClient.structures.overload(), (original, self, args) => {
        msg("homekit", "HomeClient.structures", "HomeClient.structures()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }

    try {
      patch(HomeClient.devices.overload(), (original, self, args) => {
        msg("homekit", "HomeClient.devices", "HomeClient.devices()");
        return original.call(self, ...args);
      });
    } catch { /* overload unavailable */ }
  } catch { /* GMS unavailable */ }
}

function hookActivityRecognition() {
  try {
    const ARC = Java.use("com.google.android.gms.location.ActivityRecognitionClient");

    try {
      patch(
        ARC.requestActivityUpdates.overload("long", "android.app.PendingIntent"),
        (original, self, args) => {
          msg("activity_recognition", "ActivityRecognitionClient.requestActivityUpdates",
            "ActivityRecognitionClient.requestActivityUpdates()");
          return original.call(self, ...args);
        },
      );
    } catch { /* overload unavailable */ }

    try {
      patch(
        ARC.requestActivityTransitionUpdates.overload(
          "com.google.android.gms.location.ActivityTransitionRequest",
          "android.app.PendingIntent",
        ),
        (original, self, args) => {
          msg("activity_recognition", "ActivityRecognitionClient.requestActivityTransitionUpdates",
            "ActivityRecognitionClient.requestActivityTransitionUpdates()");
          return original.call(self, ...args);
        },
      );
    } catch { /* overload unavailable */ }
  } catch { /* GMS unavailable */ }
}

function hookUsageStats() {
  try {
    const UsageStatsManager = Java.use("android.app.usage.UsageStatsManager");

    try {
      patch(
        UsageStatsManager.queryUsageStats.overload("int", "long", "long"),
        (original, self, args) => {
          msg("usage_stats", "UsageStatsManager.queryUsageStats",
            "UsageStatsManager.queryUsageStats()");
          return original.call(self, ...args);
        },
      );
    } catch { /* overload unavailable */ }

    try {
      patch(
        UsageStatsManager.queryEvents.overload("long", "long"),
        (original, self, args) => {
          msg("usage_stats", "UsageStatsManager.queryEvents",
            "UsageStatsManager.queryEvents()");
          return original.call(self, ...args);
        },
      );
    } catch { /* overload unavailable */ }
  } catch { /* class unavailable */ }
}

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    const fns = [
      hookMicrophone,
      hookCamera,
      hookPhotos,
      hookSensors,
      hookBluetooth,
      hookWifi,
      hookLocation,
      hookHealth,
      hookGameCenter,
      hookHome,
      hookActivityRecognition,
      hookUsageStats,
    ];

    for (const fn of fns) {
      try {
        fn();
      } catch (e) {
        console.warn(`privacy: ${fn.name} failed:`, e);
      }
    }
  });
}

export function stop() {
  Java.perform(() => {
    for (let i = restores.length - 1; i >= 0; i--) {
      try {
        restores[i]();
      } catch { /* ignore */ }
    }
  });
  restores.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  return Java.available;
}

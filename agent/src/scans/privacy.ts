import ObjC from 'frida-objc-bridge'

const groups = {
  Bluetooth: [
    'NSBluetoothAlwaysUsageDescription',
    'NSBluetoothPeripheralUsageDescription', // deperecated
  ],
  Calendar: [
    'NSCalendarsUsageDescription',
    'NSRemindersUsageDescription',
  ],
  Camera: [
    'NSCameraUsageDescription',
  ],
  Microphone: [
    'NSMicrophoneUsageDescription',
  ],
  Contacts: [
    'NSContactsUsageDescription',
  ],
  Biometrics: [
    'NSFaceIDUsageDescription',
  ],
  GameCenter: [
    'NSGKFriendListUsageDescription',
  ],
  Health: [
    'NSHealthClinicalHealthRecordsShareUsageDescription',
    'NSHealthShareUsageDescription',
    'NSHealthUpdateUsageDescription',
    'NSHealthRequiredReadAuthorizationTypeIdentifiers',
  ],
  Home: [
    'NSHomeKitUsageDescription',
  ],
  Location: [
    'NSLocationAlwaysAndWhenInUseUsageDescription',
    'NSLocationUsageDescription',
    'NSLocationWhenInUseUsageDescription',
    'NSLocationTemporaryUsageDescriptionDictionary',
    'NSLocationAlwaysUsageDescription',
    'NSWidgetWantsLocation',
    'NSLocationDefaultAccuracyReduced',
  ],
  Music: [
    'NSAppleMusicUsageDescription',
  ],
  Motion: [
    'NSMotionUsageDescription',
    'NSFallDetectionUsageDescription',
  ],
  Network: [
    'NSLocalNetworkUsageDescription',
    'NSNearbyInteractionUsageDescription',
    'NSNearbyInteractionAllowOnceUsageDescription'
  ],
  NFC: [
    'NFCReaderUsageDescription',
  ],
  Photos: [
    'NSPhotoLibraryAddUsageDescription',
    'NSPhotoLibraryUsageDescription',
  ],
  Tracking: [
    'NSUserTrackingUsageDescription',
  ],
  Sensor: [
    'NSSensorKitUsageDescription',
  ],
  Siri: [
    'NSSiriUsageDescription'
  ],
  Speech: [
    'NSSpeechRecognitionUsageDescription'
  ],
  TV: [
    'NSVideoSubscriberAccountUsageDescription'
  ],
  WiFi: [
    'UIRequiresPersistentWiFi'
  ]
}

export function usage() {
  const dict = ObjC.classes.NSBundle.mainBundle().infoDictionary()
  const result: { [key: string]: { [key: string]: string } } = {}
  for (const [group, keys] of Object.entries(groups)) {
    const inner: {[key: string]: string} = {}
    for (const key of keys) {
      const description = dict.objectForKey_(key)
      if (description) {
        inner[key] = description + ''
      }
    }

    if (Object.keys(inner).length) {
      result[group] = inner
    }
  }

  return result
}

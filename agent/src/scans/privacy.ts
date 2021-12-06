const groups = {
  bluetooth: [
    'NSBluetoothAlwaysUsageDescription',
    'NSBluetoothPeripheralUsageDescription', // deperecated
  ],
  calendar: [
    'NSCalendarsUsageDescription',
    'NSRemindersUsageDescription',
  ],
  camera: [
    'NSCameraUsageDescription',
  ],
  mic: [
    'NSMicrophoneUsageDescription',
  ],
  contacts: [
    'NSContactsUsageDescription',
  ],
  bio: [
    'NSFaceIDUsageDescription',
  ],
  gameCenter: [
    'NSGKFriendListUsageDescription',
  ],
  health: [
    'NSHealthClinicalHealthRecordsShareUsageDescription',
    'NSHealthShareUsageDescription',
    'NSHealthUpdateUsageDescription',
    'NSHealthRequiredReadAuthorizationTypeIdentifiers',
  ],
  home: [
    'NSHomeKitUsageDescription',
  ],
  location: [
    'NSLocationAlwaysAndWhenInUseUsageDescription',
    'NSLocationUsageDescription',
    'NSLocationWhenInUseUsageDescription',
    'NSLocationTemporaryUsageDescriptionDictionary',
    'NSLocationAlwaysUsageDescription',
    'NSWidgetWantsLocation',
    'NSLocationDefaultAccuracyReduced',
  ],
  music: [
    'NSAppleMusicUsageDescription',
  ],
  motion: [
    'NSMotionUsageDescription',
    'NSFallDetectionUsageDescription',
  ],
  network: [
    'NSLocalNetworkUsageDescription',
    'NSNearbyInteractionUsageDescription',
    'NSNearbyInteractionAllowOnceUsageDescription'
  ],
  nfc: [
    'NFCReaderUsageDescription',
  ],
  photos: [
    'NSPhotoLibraryAddUsageDescription',
    'NSPhotoLibraryUsageDescription',
  ],
  tracking: [
    'NSUserTrackingUsageDescription',
  ],
  sensor: [
    'NSSensorKitUsageDescription',
  ],
  siri: [
    'NSSiriUsageDescription'
  ],
  speech: [
    'NSSpeechRecognitionUsageDescription'
  ],
  tv: [
    'NSVideoSubscriberAccountUsageDescription'
  ],
  wifi: [
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

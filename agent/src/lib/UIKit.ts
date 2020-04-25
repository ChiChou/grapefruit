export const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double'
export const CGSize = [CGFloat, CGFloat]

// const CGPoint = CGSize
// const NSRect = [CGPoint, CGSize]

export const UIGraphicsBeginImageContextWithOptions = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsBeginImageContextWithOptions')!,
  'void', [CGSize, 'bool', CGFloat])

export const UIGraphicsGetImageFromCurrentImageContext = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsGetImageFromCurrentImageContext')!,
  'pointer', [])

export const UIGraphicsEndImageContext = new NativeFunction(
  Module.findExportByName('UIKit', 'UIGraphicsEndImageContext')!,
  'void', [])

export const UIImagePNGRepresentation = new NativeFunction(
  Module.findExportByName('UIKit', 'UIImagePNGRepresentation')!,
  'pointer', ['pointer'])

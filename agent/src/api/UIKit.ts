import { api } from './index'

// const CGPoint = CGSize
// const NSRect = [CGPoint, CGSize]

const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double'
const CGSize = [CGFloat, CGFloat]

export default api('UIKit', {
  UIGraphicsBeginImageContextWithOptions: ['void', [CGSize, 'bool', CGFloat]],
  UIGraphicsGetImageFromCurrentImageContext: ['pointer', []],
  UIGraphicsEndImageContext: ['void', []],
  UIImagePNGRepresentation: ['pointer', ['pointer']],
})

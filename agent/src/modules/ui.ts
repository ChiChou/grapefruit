import ObjC from 'frida-objc-bridge'

import { performOnMainThread } from '../lib/dispatch.js'

type Point = [number, number];
type Size = [number, number];
type Frame = [Point, Size];

interface Delegate {
  name?: string;
  description?: string;
}

interface Node {
  clazz: string;
  description?: string;
  children?: Node[];
  frame?: Frame;
  preview?: ArrayBuffer;
  delegate?: Delegate;
}

const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double'
const CGSize: NativeFunctionArgumentType = [CGFloat, CGFloat];

const UIKit = Process.getModuleByName('UIKit')
if (!UIKit) {
  throw new Error('UIKit not found')
}

const UIGraphicsBeginImageContextWithOptions = new NativeFunction(
  UIKit.findExportByName('UIGraphicsBeginImageContextWithOptions')!, 'void', [CGSize, 'bool', CGFloat]);

const UIGraphicsGetImageFromCurrentImageContext = new NativeFunction(
  UIKit.findExportByName('UIGraphicsGetImageFromCurrentImageContext')!, 'pointer', []);

const UIGraphicsEndImageContext = new NativeFunction(
  UIKit.findExportByName('UIGraphicsEndImageContext')!, 'void', []);

const UIImagePNGRepresentation = new NativeFunction(
  UIKit.findExportByName('UIImagePNGRepresentation')!, 'pointer', ['pointer']);

export function dump(includingPreview: false): Promise<Node | null> {
  const { UIWindow } = ObjC.classes
  const win = UIWindow.keyWindow()
  const recursive = (view: ObjC.Object): Node | null => {
    if (!view) return null

    const clazz = view.$className
    const description = view.description().toString()
    const subviews = view.subviews()
    const delegate: Delegate = {}
    if (typeof view.delegate === 'function') {
      const instance = view.delegate() as ObjC.Object
      if (instance) {
        delegate.name = instance.$className
        delegate.description = instance.debugDescription() + ''
      }
    }

    const frame = view.superview()?.convertRect_toView_(view.frame(), NULL) as Frame
    const children: Node[] = []

    let preview = undefined
    if (includingPreview) {
      // preview
      const bounds = view.bounds()
      const size = bounds[1]
      UIGraphicsBeginImageContextWithOptions(size, 0, 0)
      const image = UIGraphicsGetImageFromCurrentImageContext();
      UIGraphicsEndImageContext()
      const png = UIImagePNGRepresentation(image) as NativePointer
      if (!png.isNull()) {
        const data = new ObjC.Object(png)
        preview = data.base64EncodedStringWithOptions_(0).toString()
      }
    }

    for (let i = 0; i < subviews.count(); i++) {
      // todo: use async function
      const child = recursive(subviews.objectAtIndex_(i))
      if (child) children.push(child)
    }
    return {
      description,
      children,
      frame,
      delegate,
      preview,
      clazz
    }
  }

  return performOnMainThread(() => recursive(win))
}

let overlay: ObjC.Object

// NSMakePoint
// NSMakeSize
export function highlight(frame: Frame): void {
  const { UIWindow, UIView, UIColor } = ObjC.classes
  if (!frame) return

  const win = UIWindow.keyWindow()
  if (!win) return

  ObjC.schedule(ObjC.mainQueue, () => {
    if (!overlay) {
      overlay = UIView.alloc().initWithFrame_(frame)
      overlay.setBackgroundColor_(UIColor.yellowColor())
      overlay.setAlpha_(0.4)
    } else {
      overlay.removeFromSuperview()
      overlay.setFrame_(frame)
    }
    win.addSubview_(overlay)
  })
}

export async function dismissHighlight(): Promise<void> {
  if (!overlay) return
  await performOnMainThread(() => overlay.removeFromSuperview())
}

// highlight([[0,0],[375,812]])
// setTimeout(() => { dismissHighlight() }, 3000)
// setTimeout(() => { highlight([[100,100],[375,812]]) }, 1000)

export function dispose() {
  return dismissHighlight()
}
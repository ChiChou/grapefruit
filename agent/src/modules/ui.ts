import { performOnMainThread } from '../lib/dispatch'

import UIKit from '../api/UIKit'

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
      UIKit.UIGraphicsBeginImageContextWithOptions(size, 0, 0)
      const image = UIKit.UIGraphicsGetImageFromCurrentImageContext();
      UIKit.UIGraphicsEndImageContext()
      const png = UIKit.UIImagePNGRepresentation(image) as NativePointer
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
type Point = [number, number];
type Size = [number, number];
type Frame = [Point, Size];

interface Node {
  description?: string;
  children?: Node[];
  frame?: Frame;
  delegate?: string;
}

export function dump(): Node {
  const win = ObjC.classes.UIWindow.keyWindow()
  const recursive = (view: ObjC.Object): Node => {
    if (!view) return {}

    const description = view.description().toString()
    const subviews = view.subviews()
    const delegate = typeof view.delegate === 'function' ? view.delegate()?.toString() : ''
    const frame = view.superview()?.convertRect_toView_(view.frame(), NULL) as Frame
    const children: Node[] = []
    for (let i = 0; i < subviews.count(); i++) {
      children.push(recursive(subviews.objectAtIndex_(i)))
    }
    return {
      description,
      children,
      frame,
      delegate
    }
  }

  return recursive(win)
}

// const CGFloat = (Process.pointerSize === 4) ? 'float' : 'double'
// const CGSize = [CGFloat, CGFloat]
// const CGPoint = CGSize
// const NSRect = [CGPoint, CGSize]

let overlay: ObjC.Object

// NSMakePoint
// NSMakeSize
export function highlight(frame: Frame): void {
  if (!frame) return

  const win = ObjC.classes.UIWindow.keyWindow()
  if (!win) return

  ObjC.schedule(ObjC.mainQueue, () => {
    if (!overlay) {
      overlay = ObjC.classes.UIView.alloc().initWithFrame_(frame)
      overlay.setBackgroundColor_(ObjC.classes.UIColor.yellowColor())
      overlay.setAlpha_(0.4)
    } else {
      overlay.removeFromSuperview()
      overlay.setFrame_(frame)
    }
    win.addSubview_(overlay)
  })
}

export function dismissHighlight(): void {
  if (!overlay) return
  ObjC.schedule(ObjC.mainQueue, () => overlay.removeFromSuperview())
}

// highlight([[0,0],[375,812]])
// setTimeout(() => { dismissHighlight() }, 3000)
// setTimeout(() => { highlight([[100,100],[375,812]]) }, 1000)

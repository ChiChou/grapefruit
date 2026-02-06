import ObjC from "frida-objc-bridge";
import { performOnMainThread } from "@/fruity/lib/dispatch.js";

type Point = [number, number];
type Size = [number, number];
type Frame = [Point, Size];

interface UIDelegate {
  name?: string;
  description?: string;
}

export interface UIDumpNode {
  clazz: string;
  description?: string;
  children?: UIDumpNode[];
  frame: Frame | null;
  delegate?: UIDelegate;
}

export async function dump() {
  const { UIWindow } = ObjC.classes;
  const win = UIWindow.keyWindow();

  const recursive = (view: ObjC.Object): UIDumpNode | null => {
    if (!view) return null;

    const clazz = view.$className;
    const description = view.description().toString();
    const subviews = view.subviews();
    const delegate: UIDelegate = {};
    if (typeof view.delegate === "function") {
      const instance = view.delegate() as ObjC.Object;
      if (instance) {
        delegate.name = instance.$className;
        delegate.description = instance.debugDescription() + "";
      }
    }

    const frame = view
      .superview()
      ?.convertRect_toView_(view.frame(), NULL) as Frame | null;

    const children: UIDumpNode[] = [];

    for (let i = 0; i < subviews.count(); i++) {
      const child = recursive(subviews.objectAtIndex_(i));
      if (child) children.push(child);
    }

    return {
      description,
      children,
      frame,
      delegate,
      clazz,
    };
  };

  await dismissHighlight();
  return performOnMainThread(() => recursive(win));
}

let overlay: ObjC.Object | null = null;

// NSMakePoint
// NSMakeSize
export function highlight(frame: Frame): void {
  const { UIWindow, UIView, UIColor } = ObjC.classes;
  if (!frame) return;

  const win = UIWindow.keyWindow();
  if (!win) return;

  ObjC.schedule(ObjC.mainQueue, () => {
    if (!overlay) {
      overlay = UIView.alloc().initWithFrame_(frame) as ObjC.Object;
      overlay.setBackgroundColor_(UIColor.yellowColor());
      overlay.setAlpha_(0.4);
    } else {
      overlay.removeFromSuperview();
      overlay.setFrame_(frame);
    }
    win.addSubview_(overlay);
  });

  Script.bindWeak(globalThis, dismissHighlight);
}

export async function dismissHighlight() {
  return performOnMainThread(() => {
    if (!overlay) return;
    overlay.removeFromSuperview();
    overlay = null;
  });
}

// highlight([[0,0],[375,812]])
// setTimeout(() => { dismissHighlight() }, 3000)
// setTimeout(() => { highlight([[100,100],[375,812]]) }, 1000)

import ObjC from "frida-objc-bridge";
import { performOnMainThread } from "@/fruity/lib/dispatch.js";
import { RefTracker } from "@/fruity/lib/weak.js";
import uikit from "@/fruity/native/uikit.js";

import { intersection, valid, type Frame } from "@/fruity/lib/geometry.js";

interface UIDelegate {
  name?: string;
  description?: string;
}

export interface UIDumpNode {
  id: string;
  clazz: string;
  description?: string;
  children?: UIDumpNode[];
  frame: Frame | null;
  bounds: Frame;
  localFrame: Frame;
  hidden: boolean;
  alpha: number;
  text?: string;
  visible: boolean;
  clip: Frame | null;
  image?: string;
  screenshot?: string;
  selected?: string;
  preview?: { captured: number; skipped: number; errors: number };
  delegate?: UIDelegate;
}

export interface UIChanges {
  hidden?: boolean;
  alpha?: number;
  frame?: Frame;
  text?: string;
}

let refs: RefTracker | null = null;
let generation = 0;
let overlay: ObjC.Object | null = null;

function window() {
  return ObjC.classes.UIWindow.keyWindow() as ObjC.Object | null;
}

function textKind(view: ObjC.Object): "text" | "title" | null {
  if (typeof view.text === "function" && typeof view.setText_ === "function") return "text";
  if (typeof view.currentTitle === "function" && typeof view.setTitle_forState_ === "function" && typeof view.state === "function") return "title";
  return null;
}

function clearHighlight() {
  if (!overlay) return;
  overlay.removeFromSuperview();
  overlay.release();
  overlay = null;
}

function bindings() {
  const kit = Process.getModuleByName("UIKit");
  const cg = Process.getModuleByName("CoreGraphics");
  return {
    begin: new NativeFunction(kit.getExportByName("UIGraphicsBeginImageContextWithOptions"), "void", [["double", "double"], "bool", "double"]),
    context: new NativeFunction(kit.getExportByName("UIGraphicsGetCurrentContext"), "pointer", []),
    image: new NativeFunction(kit.getExportByName("UIGraphicsGetImageFromCurrentImageContext"), "pointer", []),
    end: new NativeFunction(kit.getExportByName("UIGraphicsEndImageContext"), "void", []),
    translate: new NativeFunction(cg.getExportByName("CGContextTranslateCTM"), "void", ["pointer", "double", "double"]),
    alpha: new NativeFunction(cg.getExportByName("CGColorGetAlpha"), "double", ["pointer"]),
  };
}

let graphics: ReturnType<typeof bindings> | undefined;

function native() {
  return graphics ??= bindings();
}

function capture(view: ObjC.Object, own: boolean, scale: number): string {
  const api = native();
  const bounds = view.bounds() as Frame;
  const layers: { layer: ObjC.Object; hidden: boolean }[] = [];
  const transaction = ObjC.classes.CATransaction;
  transaction.begin();
  transaction.setDisableActions_(true);
  let started = false;
  try {
    if (own) {
      const children = view.subviews();
      for (let i = 0; i < children.count(); i++) {
        const layer = children.objectAtIndex_(i).layer();
        layers.push({ layer, hidden: !!layer.isHidden() });
        layer.setHidden_(true);
      }
    }
    api.begin(bounds[1], 0, scale);
    started = true;
    const ctx = api.context();
    if (ctx.isNull()) throw new Error("Could not allocate screenshot context");
    // CALayer renders in its bounds coordinate system, including a scroll view's origin.
    api.translate(ctx, -bounds[0][0], -bounds[0][1]);
    view.layer().renderInContext_(ctx);
    const png = uikit().UIImagePNGRepresentation(api.image());
    if (png.isNull()) throw new Error("Could not encode screenshot");
    return new ObjC.Object(png).base64EncodedStringWithOptions_(0).toString();
  } finally {
    if (started) api.end();
    for (const { layer, hidden } of layers) layer.setHidden_(hidden);
    transaction.commit();
  }
}

export function dump(options: { preview?: boolean; selected?: string } = {}) {
  return performOnMainThread(() => {
    let selected: ObjC.Object | null = null;
    if (options.selected?.startsWith(`ui:${generation}:`) && refs) {
      try { selected = refs.get(options.selected).retain(); }
      catch { /* The element may have disappeared since the edit. */ }
    }
    try {
      clearHighlight();
      refs?.release();
      refs = new RefTracker();
      const epoch = ++generation;
      const win = window();
      if (!win) return null;
      const screen = win.bounds() as Frame;
      let index = 0;
      let selectedId: string | undefined;
      let pixels = 0;
      let attempts = 0;
      const stats = { captured: 0, skipped: 0, errors: 0 };
      const recursive = (view: ObjC.Object, shown: boolean, clip: Frame | null): UIDumpNode => {
        const bounds = view.bounds() as Frame;
        const frame = view.convertRect_toView_(bounds, win) as Frame;
        const hidden = !!view.isHidden();
        const alpha = Number(view.alpha());
        shown = shown && !hidden && alpha > 0.01;
        const region = clip ? intersection(frame, clip) : null;
        const visible = shown && region !== null && bounds[1][0] > 0 && bounds[1][1] > 0;
        const id = `ui:${epoch}:${index++}`;
        refs!.put(id, view);
        if (selected?.handle.equals(view.handle)) selectedId = id;
        const subviews = view.subviews();
        const node: UIDumpNode = {
          id, clazz: view.$className, description: view.description().toString(),
          frame, bounds, localFrame: view.frame() as Frame, hidden, alpha, visible, clip: region, children: [],
        };
        const kind = textKind(view);
        if (kind) {
          const value = kind === "text" ? view.text() : view.currentTitle();
          node.text = value?.toString() ?? "";
        }
        if (typeof view.delegate === "function") {
          const delegate = view.delegate();
          if (delegate) node.delegate = { name: delegate.$className, description: delegate.debugDescription().toString() };
        }
        const childClip = view.clipsToBounds() ? region : clip;
        for (let i = 0; i < subviews.count(); i++) {
          node.children!.push(recursive(subviews.objectAtIndex_(i), shown, childClip));
        }
        // Prefer small content layers before spending the budget on large containers.
        // Transparent UIKit containers carry geometry but need no image buffer.
        if (!options.preview || !visible) return node;
        const color = view.backgroundColor();
        const draw = view["- drawRect:"];
        const draws = draw && !draw.implementation.equals(ObjC.classes.UIView["- drawRect:"].implementation);
        const layer = view.layer();
        const sublayers = layer.sublayers();
        const content = draws || !!layer.contents() || Number(layer.borderWidth()) > 0 ||
          Number(layer.shadowOpacity()) > 0 || (sublayers && sublayers.count() > subviews.count()) ||
          (color && native().alpha(color.CGColor()) > 0);
        if (content) {
          const scale = Math.min(1, 1024 / Math.max(...bounds[1]));
          const cost = Math.ceil(bounds[1][0] * bounds[1][1] * scale * scale);
          if (attempts < 48 && pixels + cost <= 3_000_000) {
            attempts++;
            pixels += cost;
            try { node.image = capture(view, true, scale); stats.captured++; }
            catch { stats.errors++; }
          } else stats.skipped++;
        }
        return node;
      };
      // Capture the composite before isolating individual layers.
      let screenshot: string | undefined;
      if (options.preview && screen[1].every(n => Number.isFinite(n) && n > 0)) {
        try { screenshot = capture(win, false, Math.min(1, 1024 / Math.max(...screen[1]))); }
        catch { stats.errors++; }
      }
      const root = recursive(win, true, screen);
      root.screenshot = screenshot;
      root.selected = selectedId;
      if (options.preview) root.preview = stats;
      return root;
    } finally {
      selected?.release();
    }
  });
}

export function update(id: string, changes: UIChanges) {
  if (changes.alpha !== undefined && (!Number.isFinite(changes.alpha) || changes.alpha < 0 || changes.alpha > 1))
    throw new Error("Alpha must be between 0 and 1");
  if (changes.hidden !== undefined && typeof changes.hidden !== "boolean") throw new Error("Hidden must be a boolean");
  if (changes.text !== undefined && typeof changes.text !== "string") throw new Error("Text must be a string");
  if (changes.frame !== undefined && !valid(changes.frame)) throw new Error("Invalid frame");
  return performOnMainThread(() => {
    if (!refs || !id.startsWith(`ui:${generation}:`)) throw new Error("This UI snapshot is stale. Refresh and select the element again.");
    const view = refs.get(id);
    if (!view.window()) throw new Error("This element is detached. Refresh the hierarchy.");
    const kind = changes.text !== undefined ? textKind(view) : null;
    if (changes.text !== undefined && !kind) throw new Error("This element does not support editing text");
    if (changes.frame) view.setFrame_(changes.frame);
    if (changes.alpha !== undefined) view.setAlpha_(changes.alpha);
    if (changes.hidden !== undefined) view.setHidden_(changes.hidden);
    if (changes.text !== undefined) {
      if (kind === "text") view.setText_(changes.text);
      else view.setTitle_forState_(changes.text, view.state());
    }
  });
}

export function highlight(frame: Frame): Promise<void> {
  return performOnMainThread(() => {
    const win = window();
    if (!win || !frame) return;
    clearHighlight();
    overlay = ObjC.classes.UIView.alloc().initWithFrame_(frame);
    overlay!.setBackgroundColor_(ObjC.classes.UIColor.yellowColor());
    overlay!.setAlpha_(0.4);
    overlay!.setUserInteractionEnabled_(false);
    win.addSubview_(overlay);
  });
}

export function dismissHighlight() {
  return performOnMainThread(clearHighlight);
}

Script.bindWeak(globalThis, () => {
  refs?.release();
  void dismissHighlight();
});

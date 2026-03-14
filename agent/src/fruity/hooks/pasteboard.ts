import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";

// Helper to get pasteboard name
const getPasteboardInfo = (
  self: ObjC.Object,
): { name: string; isGeneral: boolean; shortName: string } => {
  try {
    const name = self.name()?.toString() || "unknown";
    const isGeneral = name === "com.apple.UIKit.pboard.general";
    const shortName = isGeneral ? "generalPasteboard" : name;
    return { name, isGeneral, shortName };
  } catch {
    return { name: "unknown", isGeneral: false, shortName: "unknown" };
  }
};

/**
 * Hook UIPasteboard operations to monitor clipboard access
 */
export function monitor() {
  if (!ObjC.available) return [];

  const hooks: InvocationListener[] = [];
  const UIPasteboard = ObjC.classes.UIPasteboard;
  if (!UIPasteboard) return [];

  // Hook string getter
  const stringGetter = UIPasteboard["- string"];
  if (stringGetter) {
    hooks.push(
      Interceptor.attach(stringGetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
        },
        onLeave(retval) {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);
          let content: ArrayBuffer | null = null;

          if (!retval.isNull()) {
            const str = new ObjC.Object(retval);
            try {
              const data = str.dataUsingEncoding_(4); // NSUTF8StringEncoding
              if (data && !data.isNull()) {
                content = data.bytes().readByteArray(data.length());
              }
            } catch {
              // ignore
            }
          }

          send(
            {
              subject: "hook",
              category: "pasteboard",
              symbol: "-[UIPasteboard string]",
              dir: "leave",
              line: `[${shortName} string] // read`,
              backtrace: bt(this.context),
              extra: {
                op: "read",
                pasteboardName: name,
                isGeneral,
                contentType: "string",
              },
            },
            content,
          );
        },
      }),
    );
  }

  // Hook strings getter (array)
  const stringsGetter = UIPasteboard["- strings"];
  if (stringsGetter) {
    hooks.push(
      Interceptor.attach(stringsGetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
        },
        onLeave() {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);

          send({
            subject: "hook",
            category: "pasteboard",
            symbol: "-[UIPasteboard strings]",
            dir: "leave",
            line: `[${shortName} strings] // read`,
            backtrace: bt(this.context),
            extra: {
              op: "read",
              pasteboardName: name,
              isGeneral,
              contentType: "strings",
            },
          });
        },
      }),
    );
  }

  // Hook string setter
  const stringSetter = UIPasteboard["- setString:"];
  if (stringSetter) {
    hooks.push(
      Interceptor.attach(stringSetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
          this.content = null;

          if (!args[2].isNull()) {
            const str = new ObjC.Object(args[2]);
            try {
              const data = str.dataUsingEncoding_(4);
              if (data && !data.isNull()) {
                this.content = data.bytes().readByteArray(data.length());
              }
            } catch {
              // ignore
            }
          }
        },
        onLeave() {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);

          send(
            {
              subject: "hook",
              category: "pasteboard",
              symbol: "-[UIPasteboard setString:]",
              dir: "leave",
              line: `[${shortName} setString:...] // write`,
              backtrace: bt(this.context),
              extra: {
                op: "write",
                pasteboardName: name,
                isGeneral,
                contentType: "string",
              },
            },
            this.content,
          );
        },
      }),
    );
  }

  // Hook data getter
  const dataGetter = UIPasteboard["- dataForPasteboardType:"];
  if (dataGetter) {
    hooks.push(
      Interceptor.attach(dataGetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
          this.pbType = new ObjC.Object(args[2]).toString();
        },
        onLeave(retval) {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);
          let content: ArrayBuffer | null = null;

          if (!retval.isNull()) {
            const data = new ObjC.Object(retval);
            try {
              content = data.bytes().readByteArray(data.length());
            } catch {
              // ignore
            }
          }

          send(
            {
              subject: "hook",
              category: "pasteboard",
              symbol: "-[UIPasteboard dataForPasteboardType:]",
              dir: "leave",
              line: `[${shortName} dataForPasteboardType:"${this.pbType}"] // read`,
              backtrace: bt(this.context),
              extra: {
                op: "read",
                pasteboardName: name,
                isGeneral,
                contentType: this.pbType,
              },
            },
            content,
          );
        },
      }),
    );
  }

  // Hook data setter
  const dataSetter = UIPasteboard["- setData:forPasteboardType:"];
  if (dataSetter) {
    hooks.push(
      Interceptor.attach(dataSetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
          this.pbType = new ObjC.Object(args[3]).toString();
          this.content = null;

          if (!args[2].isNull()) {
            const data = new ObjC.Object(args[2]);
            try {
              this.content = data.bytes().readByteArray(data.length());
            } catch {
              // ignore
            }
          }
        },
        onLeave() {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);

          send(
            {
              subject: "hook",
              category: "pasteboard",
              symbol: "-[UIPasteboard setData:forPasteboardType:]",
              dir: "leave",
              line: `[${shortName} setData:... forPasteboardType:"${this.pbType}"] // write`,
              backtrace: bt(this.context),
              extra: {
                op: "write",
                pasteboardName: name,
                isGeneral,
                contentType: this.pbType,
              },
            },
            this.content,
          );
        },
      }),
    );
  }

  // Hook items setter (general purpose)
  const itemsSetter = UIPasteboard["- setItems:"];
  if (itemsSetter) {
    hooks.push(
      Interceptor.attach(itemsSetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
        },
        onLeave() {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);

          send({
            subject: "hook",
            category: "pasteboard",
            symbol: "-[UIPasteboard setItems:]",
            dir: "leave",
            line: `[${shortName} setItems:...] // write`,
            backtrace: bt(this.context),
            extra: {
              op: "write",
              pasteboardName: name,
              isGeneral,
              contentType: "items",
            },
          });
        },
      }),
    );
  }

  // Hook URL getter
  const urlGetter = UIPasteboard["- URL"];
  if (urlGetter) {
    hooks.push(
      Interceptor.attach(urlGetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
        },
        onLeave(retval) {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);
          let content: ArrayBuffer | null = null;

          if (!retval.isNull()) {
            const url = new ObjC.Object(retval);
            try {
              const str = url.absoluteString();
              if (str) {
                const data = str.dataUsingEncoding_(4);
                if (data && !data.isNull()) {
                  content = data.bytes().readByteArray(data.length());
                }
              }
            } catch {
              // ignore
            }
          }

          send(
            {
              subject: "hook",
              category: "pasteboard",
              symbol: "-[UIPasteboard URL]",
              dir: "leave",
              line: `[${shortName} URL] // read`,
              backtrace: bt(this.context),
              extra: {
                op: "read",
                pasteboardName: name,
                isGeneral,
                contentType: "URL",
              },
            },
            content,
          );
        },
      }),
    );
  }

  // Hook image getter
  const imageGetter = UIPasteboard["- image"];
  if (imageGetter) {
    hooks.push(
      Interceptor.attach(imageGetter.implementation, {
        onEnter(args) {
          this.self = new ObjC.Object(args[0]);
        },
        onLeave() {
          const { name, isGeneral, shortName } = getPasteboardInfo(this.self);

          send({
            subject: "hook",
            category: "pasteboard",
            symbol: "-[UIPasteboard image]",
            dir: "leave",
            line: `[${shortName} image] // read`,
            backtrace: bt(this.context),
            extra: {
              op: "read",
              pasteboardName: name,
              isGeneral,
              contentType: "image",
            },
          });
        },
      }),
    );
  }

  return hooks;
}

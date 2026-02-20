// this script is based on the article
// https://kibty.town/blog/arc/

import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { toJS } from "@/fruity/bridge/object.js";

interface WhereClause {
  field: string;
  value: string;
}

interface QueryInfo {
  type: "collection" | "doc";
  path: string;
  whereClauses: WhereClause[];
}

const queryStack: QueryInfo[] = [];

function formatQuery(q: QueryInfo) {
  return (
    `firebase.${q.type}("${q.path}")` +
    q.whereClauses
      .map((c) => `.where("${c.field}", "==", "${c.value}")`)
      .join("")
  );
}

function hookCollection(): InvocationListener[] {
  const cls = ObjC.classes.FIRFirestore;
  if (!cls) return [];
  const method = cls["- collectionWithPath:"];
  if (!method) return [];

  return [
    Interceptor.attach(method.implementation, {
      onEnter(args) {
        const path = new ObjC.Object(args[2]).toString();
        queryStack.push({ type: "collection", path, whereClauses: [] });
      },
    }),
  ];
}

function hookDocument(): InvocationListener[] {
  const cls = ObjC.classes.FIRCollectionReference;
  if (!cls) return [];
  const method = cls["- documentWithPath:"];
  if (!method) return [];

  return [
    Interceptor.attach(method.implementation, {
      onEnter(args) {
        const parent = new ObjC.Object(args[0]);
        const docPath = new ObjC.Object(args[2]).toString();
        const fullPath = parent.path().toString() + "/" + docPath;
        const q: QueryInfo = { type: "doc", path: fullPath, whereClauses: [] };
        queryStack.push(q);

        send({
          subject: "hook",
          category: "firebase",
          symbol: "-[FIRCollectionReference documentWithPath:]",
          dir: "enter",
          line: formatQuery(q),
          backtrace: bt(this.context),
          extra: { op: "doc", path: fullPath },
        });
      },
    }),
  ];
}

function hookWhere(): InvocationListener[] {
  const cls = ObjC.classes.FIRQuery;
  if (!cls) return [];
  const method = cls["- queryWhereField:isEqualTo:"];
  if (!method) return [];

  return [
    Interceptor.attach(method.implementation, {
      onEnter(args) {
        const field = new ObjC.Object(args[2]).toString();
        const value = new ObjC.Object(args[3]).toString();
        if (queryStack.length > 0) {
          queryStack[queryStack.length - 1].whereClauses.push({ field, value });
        }
      },
    }),
  ];
}

function hookExec(): InvocationListener[] {
  const cls = ObjC.classes.FIRQuery;
  if (!cls) return [];

  const hooks: InvocationListener[] = [];
  const selectors = [
    "- getDocuments",
    "- addSnapshotListener:",
    "- getDocument",
    "- addDocumentSnapshotListener:",
    "- getDocumentsWithCompletion:",
    "- getDocumentWithCompletion:",
  ];

  for (const sel of selectors) {
    const method = cls[sel];
    if (!method) continue;

    hooks.push(
      Interceptor.attach(method.implementation, {
        onEnter(args) {
          if (queryStack.length === 0) return;
          const q = queryStack.pop()!;
          send({
            subject: "hook",
            category: "firebase",
            symbol: `-[FIRQuery ${sel.slice(2)}]`,
            dir: "enter",
            line: formatQuery(q),
            backtrace: bt(this.context),
            extra: { op: "query", ...q },
          });
        },
      }),
    );
  }

  return hooks;
}

/**
 * Hook Firestore query operations: collection/doc lookups, where clauses, query execution
 */
export function query(): InvocationListener[] {
  if (!ObjC.available) return [];
  return [
    ...hookCollection(),
    ...hookDocument(),
    ...hookWhere(),
    ...hookExec(),
  ];
}

/**
 * Hook Firestore document write operations: setData, updateData
 */
export function write(): InvocationListener[] {
  if (!ObjC.available) return [];

  const hooks: InvocationListener[] = [];
  const FIRDocumentReference = ObjC.classes.FIRDocumentReference;
  if (!FIRDocumentReference) return [];

  const methods = [
    { sel: "- updateData:completion:", type: "update" },
    { sel: "- updateData:", type: "update" },
    { sel: "- setData:completion:", type: "set" },
    { sel: "- setData:", type: "set" },
  ];

  for (const m of methods) {
    const method = FIRDocumentReference[m.sel];
    if (method) {
      hooks.push(
        Interceptor.attach(method.implementation, {
          onEnter(args) {
            const docRef = new ObjC.Object(args[0]);
            const data = new ObjC.Object(args[2]);
            const fullPath = docRef.path().toString();
            send({
              subject: "hook",
              category: "firebase",
              symbol: `-[FIRDocumentReference ${m.sel.slice(2)}]`,
              dir: "enter",
              line: `firebase.doc("${fullPath}").${m.type}(${JSON.stringify(toJS(data))})`,
              backtrace: bt(this.context),
              extra: { op: m.type, path: fullPath },
            });
          },
        }),
      );
    }
  }

  return hooks;
}

import { useState } from "react";
import type { IDockviewPanelProps } from "dockview";

import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { useDock } from "@/context/DockContext";
import { usePlatformQuery } from "@/lib/queries";

import type { Il2CppClassDetail } from "@agent/common/il2cpp";

type Tab = "fields" | "methods" | "hierarchy" | "interfaces" | "nested";

const tabs: { key: Tab; label: string }[] = [
  { key: "fields", label: "Fields" },
  { key: "methods", label: "Methods" },
  { key: "hierarchy", label: "Hierarchy" },
  { key: "interfaces", label: "Interfaces" },
  { key: "nested", label: "Nested" },
];

export function Il2CppClassDetailTab(
  props: IDockviewPanelProps<{ assemblyName: string; fullName: string }>,
) {
  const { assemblyName, fullName } = props.params;
  const { openFilePanel } = useDock();
  const [activeTab, setActiveTab] = useState<Tab>("fields");

  const { data: detail, isLoading } = usePlatformQuery(
    ["il2cpp", "classDetail", assemblyName, fullName],
    (api) => api.il2cpp.classDetail(assemblyName, fullName),
  );

  if (isLoading || !detail) {
    return (
      <div className="p-4 space-y-3">
        <Skeleton className="h-6 w-2/3" />
        <Skeleton className="h-4 w-1/2" />
        {Array.from({ length: 10 }).map((_, i) => (
          <Skeleton key={i} className="h-5 w-full" />
        ))}
      </div>
    );
  }

  const { info } = detail;
  const kind = info.isEnum
    ? "enum"
    : info.isStruct
      ? "struct"
      : info.isInterface
        ? "interface"
        : "class";

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-3 border-b border-border/50 space-y-1">
        <div className="text-base font-semibold font-mono">{info.fullName}</div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>Assembly: {info.assemblyName}</span>
          <span>Kind: {kind}</span>
          {detail.parent && <span>Parent: {detail.parent}</span>}
          <span>Size: {info.instanceSize}B</span>
          {info.isAbstract && <span className="text-yellow-600">abstract</span>}
          {info.isGeneric && <span className="text-blue-600">generic</span>}
        </div>
        <div className="flex gap-2 pt-1">
          <Button
            variant="outline"
            size="sm"
            className="h-6 text-xs"
            onClick={() =>
              openFilePanel({
                id: `il2cpp_dump_${assemblyName}_${fullName}`,
                component: "il2cppClassDump",
                title: `Dump: ${fullName}`,
                params: { assemblyName, fullName },
              })
            }
          >
            Dump C#
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border/50">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className={`px-4 py-2 text-sm transition-colors ${
              activeTab === tab.key
                ? "border-b-2 border-primary text-primary font-medium"
                : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
            {tab.key === "fields" && ` (${detail.fields.length})`}
            {tab.key === "methods" && ` (${detail.methods.length})`}
            {tab.key === "interfaces" && ` (${detail.interfaces.length})`}
            {tab.key === "nested" && ` (${detail.nestedClasses.length})`}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {activeTab === "fields" && <FieldsView fields={detail.fields} />}
        {activeTab === "methods" && <MethodsView methods={detail.methods} />}
        {activeTab === "hierarchy" && (
          <HierarchyView parent={detail.parent} className={info.fullName} />
        )}
        {activeTab === "interfaces" && (
          <ListItems items={detail.interfaces} emptyText="No interfaces" />
        )}
        {activeTab === "nested" && (
          <ListItems items={detail.nestedClasses} emptyText="No nested classes" />
        )}
      </div>
    </div>
  );
}

// ── Sub-views ──

function FieldsView({
  fields,
}: {
  fields: Il2CppClassDetail["fields"];
}) {
  if (fields.length === 0)
    return <Empty text="No fields" />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-muted/50 sticky top-0">
            <th className="px-3 py-1.5 text-left font-medium">Name</th>
            <th className="px-3 py-1.5 text-left font-medium">Type</th>
            <th className="px-3 py-1.5 text-left font-medium">Offset</th>
            <th className="px-3 py-1.5 text-left font-medium">Flags</th>
          </tr>
        </thead>
        <tbody>
          {fields.map((f, i) => (
            <tr
              key={i}
              className="border-t border-border/50 hover:bg-accent/30"
            >
              <td className="px-3 py-1.5 font-mono">{f.name}</td>
              <td className="px-3 py-1.5 font-mono text-blue-600 dark:text-blue-400">
                {f.typeName}
              </td>
              <td className="px-3 py-1.5 font-mono text-muted-foreground">
                {f.isStatic
                  ? "static"
                  : f.isLiteral
                    ? "const"
                    : `0x${f.offset.toString(16)}`}
              </td>
              <td className="px-3 py-1.5 text-xs text-muted-foreground">
                {f.modifier}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MethodsView({
  methods,
}: {
  methods: Il2CppClassDetail["methods"];
}) {
  if (methods.length === 0)
    return <Empty text="No methods" />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-muted/50 sticky top-0">
            <th className="px-3 py-1.5 text-left font-medium">Name</th>
            <th className="px-3 py-1.5 text-left font-medium">Return</th>
            <th className="px-3 py-1.5 text-left font-medium">Parameters</th>
            <th className="px-3 py-1.5 text-left font-medium">RVA</th>
            <th className="px-3 py-1.5 text-left font-medium">Flags</th>
          </tr>
        </thead>
        <tbody>
          {methods.map((m, i) => (
            <tr
              key={i}
              className="border-t border-border/50 hover:bg-accent/30"
            >
              <td className="px-3 py-1.5 font-mono">
                {m.isStatic && (
                  <span className="text-yellow-600 text-xs mr-1">static</span>
                )}
                {m.name}
              </td>
              <td className="px-3 py-1.5 font-mono text-blue-600 dark:text-blue-400">
                {m.returnType}
              </td>
              <td className="px-3 py-1.5 font-mono text-xs text-muted-foreground">
                {m.parameters.length === 0
                  ? "()"
                  : `(${m.parameters.map((p) => `${p.typeName} ${p.name}`).join(", ")})`}
              </td>
              <td className="px-3 py-1.5 font-mono text-xs text-muted-foreground">
                {m.rva || "—"}
              </td>
              <td className="px-3 py-1.5 text-xs text-muted-foreground">
                {m.modifier}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HierarchyView({
  parent,
  className,
}: {
  parent: string | null;
  className: string;
}) {
  const chain: string[] = [];
  if (parent) chain.push(parent);
  chain.push(className);

  return (
    <div className="p-4 space-y-1">
      {chain.map((name, i) => (
        <div
          key={i}
          className="font-mono text-sm"
          style={{ paddingLeft: `${i * 1.5}rem` }}
        >
          {i > 0 && (
            <span className="text-muted-foreground mr-1">└─</span>
          )}
          <span className={i === chain.length - 1 ? "font-semibold text-primary" : ""}>
            {name}
          </span>
        </div>
      ))}
    </div>
  );
}

function ListItems({ items, emptyText }: { items: string[]; emptyText: string }) {
  if (items.length === 0)
    return <Empty text={emptyText} />;

  return (
    <div className="p-2">
      {items.map((item, i) => (
        <div
          key={i}
          className="px-3 py-1.5 text-sm font-mono hover:bg-accent/30 rounded"
        >
          {item}
        </div>
      ))}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
      {text}
    </div>
  );
}

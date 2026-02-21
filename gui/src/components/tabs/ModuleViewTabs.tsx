import type { IDockviewPanelProps } from "dockview";

import { ImportsListView } from "../views/ImportsListView";
import { SectionsListView } from "../views/SectionsListView";
import { ClassesListView } from "../views/ClassesListView";
import { SymbolsListView } from "../views/SymbolsListView";
import { ExportedListView } from "../views/ExportedListView";

interface ModuleViewParams {
  path: string;
}

export function ModuleImportsTab({
  params,
}: IDockviewPanelProps<ModuleViewParams>) {
  return (
    <div className="h-full flex flex-col p-4 overflow-hidden">
      <ImportsListView path={params.path} />
    </div>
  );
}

export function ModuleSectionsTab({
  params,
}: IDockviewPanelProps<ModuleViewParams>) {
  return (
    <div className="h-full flex flex-col p-4 overflow-hidden">
      <SectionsListView path={params.path} />
    </div>
  );
}

export function ModuleClassesTab({
  params,
}: IDockviewPanelProps<ModuleViewParams>) {
  return (
    <div className="h-full flex flex-col p-4 overflow-hidden">
      <ClassesListView path={params.path} />
    </div>
  );
}

export function ModuleSymbolsTab({
  params,
}: IDockviewPanelProps<ModuleViewParams>) {
  return (
    <div className="h-full flex flex-col p-4 overflow-hidden">
      <SymbolsListView path={params.path} />
    </div>
  );
}

export function ModuleExportedTab({
  params,
}: IDockviewPanelProps<ModuleViewParams>) {
  return (
    <div className="h-full flex flex-col p-4 overflow-hidden">
      <ExportedListView path={params.path} />
    </div>
  );
}

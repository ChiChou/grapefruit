import type { IDockviewPanelProps } from "dockview";

export interface ModuleDetailParams {
  path: string;
}

export function ModuleDetailTab({
  params,
}: IDockviewPanelProps<ModuleDetailParams>) {
  return (
    <div className="h-full flex flex-col p-4">
      <h2 className="text-xl font-semibold mb-4">{params.path}</h2>
    </div>
  );
}

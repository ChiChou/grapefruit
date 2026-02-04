import type { IDockviewPanelHeaderProps } from "dockview";

export function NoCloseTabHeader({ api }: IDockviewPanelHeaderProps) {
  return (
    <div className="dv-default-tab">
      <span className="dv-default-tab-content">{api.title}</span>
    </div>
  );
}

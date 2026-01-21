import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Search } from "lucide-react";

import { Status, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import type { Section } from "../../../../agent/types/fruity/modules/symbol";

export interface ModuleDetailParams {
  path: string;
}

type TabKey = "dependencies" | "sections" | "symbols" | "imported" | "exported" | "classes";

interface SymbolLike {
  name: string;
  addr?: string;
  demangled: string | null;
}

interface TabData {
  dependencies: string[] | null;
  sections: Section[] | null;
  symbols: SymbolLike[] | null;
  imported: SymbolLike[] | null;
  exported: SymbolLike[] | null;
  classes: string[] | null;
}

type SymbolTabKey = "symbols" | "imported" | "exported";

function SymbolTable({
  items,
  search,
  onSearchChange,
}: {
  items: SymbolLike[];
  search: string;
  onSearchChange: (value: string) => void;
}) {
  const { t } = useTranslation();

  const filtered = useMemo(() => {
    if (!search.trim()) return items;
    const query = search.toLowerCase();
    return items.filter(
      (item) =>
        item.name.toLowerCase().includes(query) ||
        (item.demangled && item.demangled.toLowerCase().includes(query)),
    );
  }, [items, search]);

  return (
    <div className="flex flex-col h-full">
      <div className="relative mb-2">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <Input
          placeholder={t("search")}
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9"
        />
      </div>
      <div className="overflow-auto flex-1">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("name")}</TableHead>
              <TableHead>{t("address")}</TableHead>
              <TableHead>{t("demangled")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((item, idx) => (
              <TableRow key={item.addr || idx}>
                <TableCell className="font-mono text-xs">{item.name}</TableCell>
                <TableCell className="font-mono text-xs">
                  {item.addr || "-"}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {item.demangled || "-"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export function ModuleDetailTab({
  params,
}: IDockviewPanelProps<ModuleDetailParams>) {
  const { api, status } = useSession();
  const { openFilePanel } = useDock();
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<TabKey>("sections");
  const [searchState, setSearchState] = useState<Record<SymbolTabKey | "classes", string>>({
    symbols: "",
    imported: "",
    exported: "",
    classes: "",
  });
  const [loading, setLoading] = useState<Record<TabKey, boolean>>({
    dependencies: false,
    sections: false,
    symbols: false,
    imported: false,
    exported: false,
    classes: false,
  });
  const [data, setData] = useState<TabData>({
    dependencies: null,
    sections: null,
    symbols: null,
    imported: null,
    exported: null,
    classes: null,
  });

  const loadTabData = useCallback(
    async (tab: TabKey) => {
      if (status !== Status.Ready || !api) return;
      if (data[tab] !== null) return; // Already loaded

      setLoading((prev) => ({ ...prev, [tab]: true }));
      try {
        let result: unknown[];
        switch (tab) {
          case "dependencies":
            result = await api.symbol.dependencies(params.path);
            break;
          case "sections":
            result = await api.symbol.sections(params.path);
            break;
          case "symbols":
            result = await api.symbol.symbols(params.path);
            break;
          case "imported":
            result = await api.symbol.imports(params.path);
            break;
          case "exported":
            result = await api.symbol.exports(params.path);
            break;
          case "classes":
            result = await api.classdump.classesForModule(params.path);
            break;
        }
        setData((prev) => ({ ...prev, [tab]: result }));
      } catch (err) {
        console.error(`Failed to load ${tab}:`, err);
        setData((prev) => ({ ...prev, [tab]: [] }));
      } finally {
        setLoading((prev) => ({ ...prev, [tab]: false }));
      }
    },
    [api, status, params.path, data],
  );

  // Load data when tab changes
  useEffect(() => {
    loadTabData(activeTab);
  }, [activeTab, loadTabData]);

  // Load initial tab data
  useEffect(() => {
    if (status === Status.Ready && api) {
      loadTabData("sections");
    }
  }, [status, api, loadTabData]);

  const handleTabChange = (value: string) => {
    setActiveTab(value as TabKey);
  };

  const openModuleTab = (path: string) => {
    const name = path.split("/").pop() || path;
    openFilePanel({
      id: `module_${path}`,
      component: "moduleDetail",
      title: name,
      params: { path },
    });
  };

  const openMemoryPreviewTab = (address: string, size: number) => {
    openFilePanel({
      id: `memory_${address}_${size}`,
      component: "memory",
      title: `Memory ${address}`,
      params: { address, size },
    });
  };

  const renderSections = () => {
    if (loading.sections) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("loading")}...
        </div>
      );
    }
    const sections = data.sections;
    if (!sections || sections.length === 0) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("no_results")}
        </div>
      );
    }
    return (
      <div className="overflow-auto h-full">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("name")}</TableHead>
              <TableHead>{t("address")}</TableHead>
              <TableHead className="text-right">{t("size")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sections.map((section) => (
              <TableRow key={section.addr}>
                <TableCell className="font-mono">{section.name}</TableCell>
                <TableCell className="font-mono">
                  <button
                    type="button"
                    className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer text-left"
                    onClick={() =>
                      openMemoryPreviewTab(section.addr, section.size)
                    }
                  >
                    {section.addr}
                  </button>
                </TableCell>
                <TableCell className="font-mono text-right">
                  {"0x" + section.size.toString(16)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    );
  };

  const renderDependencies = () => {
    if (loading.dependencies) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("loading")}...
        </div>
      );
    }
    const deps = data.dependencies;
    if (!deps || deps.length === 0) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("no_results")}
        </div>
      );
    }
    return (
      <ul className="p-2 space-y-1">
        {deps.map((dep) => (
          <li key={dep}>
            <button
              type="button"
              className="text-sm text-blue-600 dark:text-blue-400 hover:underline cursor-pointer text-left"
              onClick={() => openModuleTab(dep)}
            >
              {dep}
            </button>
          </li>
        ))}
      </ul>
    );
  };

  const renderClasses = () => {
    if (loading.classes) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("loading")}...
        </div>
      );
    }
    const classes = data.classes;
    if (!classes || classes.length === 0) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("no_results")}
        </div>
      );
    }
    return (
      <ClassesList
        classes={classes}
        searchValue={searchState.classes}
        onSearchChange={(value) =>
          setSearchState((prev) => ({ ...prev, classes: value }))
        }
      />
    );
  };

  function ClassesList({
    classes,
    searchValue,
    onSearchChange,
  }: {
    classes: string[];
    searchValue: string;
    onSearchChange: (value: string) => void;
  }) {
    const filtered = useMemo(() => {
      const query = searchValue.toLowerCase();
      if (!query) return classes;
      return classes.filter((c) => c.toLowerCase().includes(query));
    }, [classes, searchValue]);

    return (
      <div className="flex flex-col h-full">
        <div className="relative mb-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            placeholder={t("search")}
            value={searchValue}
            onChange={(e) => onSearchChange(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="overflow-auto flex-1">
          <div className="flex flex-wrap gap-2 p-2">
            {filtered.map((className) => (
              <button
                key={className}
                type="button"
                className="px-3 py-1 text-sm bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded-md hover:bg-blue-200 dark:hover:bg-blue-800 cursor-pointer truncate max-w-xs"
                onClick={() =>
                  openFilePanel({
                    id: `class_${className}`,
                    component: "classDetail",
                    title: className,
                    params: { className },
                  })
                }
              >
                {className}
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const renderSymbolTab = (tabKey: SymbolTabKey) => {
    if (loading[tabKey]) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("loading")}...
        </div>
      );
    }
    const items = data[tabKey];
    if (!items || items.length === 0) {
      return (
        <div className="flex items-center justify-center h-full text-gray-500">
          {t("no_results")}
        </div>
      );
    }
    return (
      <SymbolTable
        items={items}
        search={searchState[tabKey]}
        onSearchChange={(value) =>
          setSearchState((prev) => ({ ...prev, [tabKey]: value }))
        }
      />
    );
  };

  return (
    <div className="h-full flex flex-col p-4 overflow-y-auto">
      <Tabs
        defaultValue="sections"
        value={activeTab}
        onValueChange={handleTabChange}
        className="flex-1 flex flex-col"
      >
        <div className="flex items-center justify-between gap-4 mb-2">
          <TabsList>
            <TabsTrigger value="dependencies">{t("dependencies")}</TabsTrigger>
            <TabsTrigger value="sections">{t("sections")}</TabsTrigger>
            <TabsTrigger value="classes">{t("classes")}</TabsTrigger>
            <TabsTrigger value="symbols">{t("symbols")}</TabsTrigger>
            <TabsTrigger value="imported">{t("imported")}</TabsTrigger>
            <TabsTrigger value="exported">{t("exported")}</TabsTrigger>
          </TabsList>
          <h2 className="text-sm font-thin truncate">{params.path}</h2>
        </div>
        <TabsContent value="dependencies" className="flex-1">
          {renderDependencies()}
        </TabsContent>
        <TabsContent value="sections" className="flex-1">
          {renderSections()}
        </TabsContent>
        <TabsContent value="classes" className="flex-1">
          {renderClasses()}
        </TabsContent>
        <TabsContent value="symbols" className="flex-1">
          {renderSymbolTab("symbols")}
        </TabsContent>
        <TabsContent value="imported" className="flex-1">
          {renderSymbolTab("imported")}
        </TabsContent>
        <TabsContent value="exported" className="flex-1">
          {renderSymbolTab("exported")}
        </TabsContent>
      </Tabs>
    </div>
  );
}

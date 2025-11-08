import { useParams } from "react-router";
import { useEffect, useState } from "react";

interface App {
  name: string;
  identifier: string;
  pid: number;
}

export function Workspace() {
  const { udid, identifier } = useParams();
  const [app, setApp] = useState<App | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!udid || !identifier) return;

    fetch(`/api/device/${udid}/apps`)
      .then((res) => {
        if (!res.ok) throw new Error("Failed to fetch app");
        return res.json();
      })
      .then((apps: App[]) => {
        const foundApp = apps.find((a) => a.identifier === identifier);
        if (!foundApp) throw new Error("App not found");
        setApp(foundApp);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [udid, identifier]);

  if (loading) {
    return (
      <div className="p-6">
        <p className="text-gray-600">Loading workspace...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <p className="text-red-600">Error: {error}</p>
      </div>
    );
  }

  return (
    <div className="flex h-screen flex-col">
      <div className="border-b bg-white p-4">
        <div className="flex items-center gap-3">
          <img
            src={`/api/device/${udid}/icon/${identifier}`}
            alt={app?.name}
            className="h-10 w-10 rounded-lg"
            onError={(e) => {
              e.currentTarget.src =
                "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='40' height='40'%3E%3Crect width='40' height='40' fill='%23ddd'/%3E%3C/svg%3E";
            }}
          />
          <div>
            <h1 className="text-lg font-semibold">{app?.name}</h1>
            <p className="text-sm text-gray-500">{identifier}</p>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <p className="text-gray-500">Workspace for {app?.name}</p>
      </div>
    </div>
  );
}

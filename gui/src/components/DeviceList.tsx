import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";

interface Device {
  id: string;
  type: "usb" | "tether" | "remote";
  removable: boolean;
  name: string;
}

export function DeviceList() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { udid } = useParams();

  useEffect(() => {
    fetch("/api/devices")
      .then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        setDevices(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <>
        <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">Devices</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Loading devices...
        </p>
      </>
    );
  }

  if (error) {
    return (
      <>
        <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">Devices</h2>
        <p className="text-sm text-red-500 dark:text-red-400">Error: {error}</p>
      </>
    );
  }

  return (
    <>
      <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">Devices</h2>
      {devices.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">
          No devices found
        </p>
      ) : (
        <ul className="flex gap-0 sm:flex-col sm:space-y-2">
          {devices.map((device) => (
            <li key={device.id}>
              <Link
                to={`/apps/${device.id}`}
                className={`block rounded-md px-3 py-2 text-sm transition-colors hover:bg-gray-200 dark:hover:bg-gray-700 ${
                  udid === device.id
                    ? "bg-gray-300 font-medium dark:bg-gray-700 dark:text-gray-100"
                    : "text-gray-700 dark:text-gray-300"
                }`}
              >
                {device.name || device.id}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

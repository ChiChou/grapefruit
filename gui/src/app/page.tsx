"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { ThemeToggle } from "@/components/theme-toggle";
import type { Device } from "@/schema.d.ts";

export default function Home() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchDevices() {
      try {
        const res = await fetch(`/api/devices`);
        if (!res.ok) {
          throw new Error("Failed to fetch devices");
        }
        const data = await res.json();
        setDevices(data);
      } catch (error) {
        console.error("Error fetching devices:", error);
      } finally {
        setLoading(false);
      }
    }

    fetchDevices();
  }, []);

  return (
    <div className="min-h-screen bg-background">
      <header className="p-4 border-b">
        <div className="container mx-auto flex justify-end">
          <h1 className="mr-auto">
            <Image
              src="/logo.svg"
              alt="Grapefruit"
              width={160}
              height={40}
              className="inline-block w-40 h-10 mr-2"
            />
          </h1>

          <ThemeToggle />
        </div>
      </header>

      {/* Main dashboard layout */}
      <main className="container mx-auto p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {/* Left column - Connected Devices */}
          <div className="md:col-span-1 bg-card rounded-lg shadow p-4">
            <h2 className="text-xl font-semibold mb-4">Devices</h2>
            <div className="space-y-2">
              {loading ? (
                <div className="p-3 bg-muted rounded-md">
                  <p className="text-sm">Loading devices...</p>
                </div>
              ) : devices.length === 0 ? (
                <div className="p-3 bg-muted rounded-md">
                  <p className="text-sm">No devices connected</p>
                </div>
              ) : (
                devices.map((device) => (
                  <div key={device.id} className="p-3 bg-muted rounded-md">
                    <p className="text-sm font-medium">{device.name}</p>
                    <p className="text-xs text-muted-foreground">{device.id}</p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Right column - App Icons */}
          <div className="md:col-span-3 bg-card rounded-lg shadow p-4">
            <h2 className="text-xl font-semibold mb-4">App Icons</h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {/* Placeholder for app icons */}
              <div className="aspect-square bg-muted rounded-lg flex items-center justify-center">
                <p className="text-sm text-muted-foreground">No apps</p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

import { useCallback, useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { useSession } from "@/context/SessionContext";
import { Status } from "@/context/SessionContext";
import { Button } from "@/components/ui/button";
import { useTranslation } from "react-i18next";

const MAP_PICKER_STATE = "MAP_PICKER_STATE";

interface MapState {
  center: [number, number];
  zoom: number;
}

function getStoredView(): MapState {
  try {
    const stored = localStorage.getItem(MAP_PICKER_STATE);
    if (stored) {
      const parsed = JSON.parse(stored);
      return { center: parsed.center as [number, number], zoom: parsed.zoom };
    }
  } catch {
    void 0;
  }
  return { center: [37.334392145274386, -122.00797505475639], zoom: 14 };
}

function storeView(center: [number, number], zoom: number): void {
  localStorage.setItem(MAP_PICKER_STATE, JSON.stringify({ center, zoom }));
}

export function FruityGeolocationPanel() {
  const { t } = useTranslation();
  const { fruity, status } = useSession();
  const [lat, setLat] = useState<number | null>(null);
  const [lng, setLng] = useState<number | null>(null);
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markerRef = useRef<L.Marker | null>(null);

  const stopSimulation = useCallback(async () => {
    if (!fruity) return;
    try {
      await fruity.geolocation.dismiss();
    } catch (err) {
      console.error("Failed to dismiss geolocation simulation:", err);
    }
    setLat(null);
    setLng(null);
    if (markerRef.current) {
      markerRef.current.remove();
      markerRef.current = null;
    }
  }, [fruity]);

  const fakeGeolocation = useCallback(
    async (lat: number, lng: number) => {
      if (!fruity) return;
      try {
        await fruity.geolocation.fake(lat, lng);
      } catch (err) {
        console.error("Failed to fake geolocation:", err);
      }
    },
    [fruity],
  );

  const setupMap = useCallback(() => {
    if (!mapRef.current || mapInstanceRef.current) return;

    const initialState = getStoredView();
    const map = L.map(mapRef.current).setView(
      initialState.center,
      initialState.zoom,
    );
    mapInstanceRef.current = map;

    L.tileLayer("https://b.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      minZoom: 4,
      maxZoom: 18,
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      id: "mapbox/streets-v11",
      tileSize: 512,
      zoomOffset: -1,
    }).addTo(map);

    map.on("click", async (e: L.LeafletMouseEvent) => {
      const { lat: newLat, lng: newLng } = e.latlng;
      setLat(newLat);
      setLng(newLng);

      if (markerRef.current) {
        markerRef.current.remove();
      }

      const marker = L.marker(e.latlng).addTo(map);
      markerRef.current = marker;

      // marker.bindPopup(popupContent).openPopup();
    });

    const saveView = () => {
      if (!mapInstanceRef.current) return;
      const center = mapInstanceRef.current.getCenter();
      storeView([center.lat, center.lng], mapInstanceRef.current.getZoom());
    };

    for (const event of ["zoomlevelschange", "zoomend", "moveend", "resize"]) {
      map.on(event, saveView);
    }
  }, []);

  useEffect(() => {
    if (lat !== null && lng !== null) {
      fakeGeolocation(lat, lng);
    }
  }, [lat, lng, fakeGeolocation]);

  useEffect(() => {
    if (status === Status.Ready) {
      setupMap();
    }
  }, [status, setupMap]);

  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 p-2 border-b">
        <span className="text-sm font-medium leading-8">
          {t("simulated_location")}
        </span>
        {lat !== null && lng !== null && (
          <span className="text-xs text-muted-foreground leading-8">
            {lat.toFixed(6)}, {lng.toFixed(6)}
          </span>
        )}
        {lat !== null && lng !== null && (
          <Button
            variant="destructive"
            size="sm"
            onClick={stopSimulation}
            className="ml-auto"
          >
            {t("stop")}
          </Button>
        )}
      </div>
      <div ref={mapRef} className="flex-1" style={{ minHeight: 0 }} />
    </div>
  );
}

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useSession, Status } from "@/context/SessionContext";

/** Minimal event-emitter surface for dynamic socket event binding. */
interface SocketEmitter {
  on(event: string, fn: (...args: unknown[]) => void): void;
  off(event: string, fn: (...args: unknown[]) => void): void;
}

interface UseLogStreamConfig<TEntry> {
  event: string;
  path: string;
  key: string;
  limit?: number;
  fromRecord: (record: Record<string, unknown>, id: number) => TEntry;
  fromEvent: (id: number, ...args: unknown[]) => TEntry | null;
  max?: number;
  throttle?: number;
  enabled?: boolean;
}

export function useLogStream<TEntry extends { id: number }>(
  config: UseLogStreamConfig<TEntry>,
) {
  const {
    event,
    path,
    key,
    limit = 5000,
    fromRecord,
    fromEvent,
    max = 8000,
    throttle = 100,
    enabled = true,
  } = config;

  const { socket, status, device, identifier } = useSession();

  const baseUrl = `/api/${path}/${device}/${identifier}`;

  const [entries, setEntries] = useState<TEntry[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const idRef = useRef(1);
  const pendingRef = useRef<TEntry[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Load history
  const { data: history } = useQuery<Record<string, unknown[]>>({
    queryKey: [event + "History", device, identifier],
    queryFn: async () => {
      const res = await fetch(`${baseUrl}?limit=${limit}`);
      if (!res.ok) throw new Error(`Failed to load ${event} history`);
      return res.json();
    },
    enabled: enabled && status === Status.Ready && !!device && !!identifier,
    staleTime: Infinity,
    gcTime: 0,
  });

  // Reset on session change
  useEffect(() => {
    setEntries([]);
    setSelectedId(null);
    idRef.current = 1;
    pendingRef.current = [];
  }, [device, identifier]);

  // Load historical entries
  useEffect(() => {
    const records = history?.[key];
    if (!records?.length) return;

    const next: TEntry[] = [];
    for (const record of [...records].reverse()) {
      next.push(fromRecord(record as Record<string, unknown>, idRef.current++));
    }
    setEntries(next);
  }, [history, key, fromRecord]);

  // Flush pending entries
  const flushPending = useCallback(() => {
    timerRef.current = null;
    if (pendingRef.current.length === 0) return;

    const incoming = pendingRef.current;
    pendingRef.current = [];

    setEntries((prev) => {
      const merged = [...prev, ...incoming];
      return merged.length > max ? merged.slice(-max) : merged;
    });
  }, [max]);

  // Listen for live events
  useEffect(() => {
    if (status !== Status.Ready || !socket || !enabled) return;

    const handler = (...args: unknown[]) => {
      const entry = fromEvent(idRef.current++, ...args);
      if (entry) {
        pendingRef.current.push(entry);
        if (!timerRef.current) {
          timerRef.current = setTimeout(flushPending, throttle);
        }
      }
    };

    // Socket.IO typed events don't support dynamic event names;
    // cast to plain emitter for generic binding.
    const emitter = socket as unknown as SocketEmitter;
    emitter.on(event, handler);
    return () => {
      emitter.off(event, handler);
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [status, socket, event, fromEvent, flushPending, throttle, enabled]);

  // Clear mutation
  const clearMutation = useMutation({
    mutationFn: async () => {
      if (!device || !identifier) return;
      const res = await fetch(baseUrl, { method: "DELETE" });
      if (!res.ok) throw new Error(`Failed to clear ${event}`);
    },
    onSuccess: () => {
      setEntries([]);
      setSelectedId(null);
      idRef.current = 1;
      pendingRef.current = [];
    },
  });

  const clear = useCallback(() => {
    clearMutation.mutate();
  }, [clearMutation]);

  const selectedEntry = useMemo(
    () => entries.find((e) => e.id === selectedId) ?? null,
    [entries, selectedId],
  );

  return {
    entries,
    selectedId,
    setSelectedId,
    selectedEntry,
    clear,
    clearMutation,
  };
}

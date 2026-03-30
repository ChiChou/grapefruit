import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export interface Bookmark {
  addr: string;
  label: string;
  notes?: string;
}

interface HistoryEntry {
  addr: string;
  label: string;
}

export interface R2ContextType {
  addr: string;
  seek: (addr: string, label?: string) => void;
  history: HistoryEntry[];
  historyIdx: number;
  back: () => void;
  forward: () => void;

  bookmarks: Bookmark[];
  addBookmark: (b: Bookmark) => void;
  removeBookmark: (addr: string) => void;

  showBytes: boolean;
  setShowBytes: (v: boolean) => void;
}

const noop = () => {};
const R2Ctx = createContext<R2ContextType>({
  addr: "",
  seek: noop,
  history: [],
  historyIdx: -1,
  back: noop,
  forward: noop,
  bookmarks: [],
  addBookmark: noop,
  removeBookmark: noop,
  showBytes: false,
  setShowBytes: noop,
});

export const useR2 = () => useContext(R2Ctx);

function loadJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

export function R2Provider({
  storageKey,
  children,
}: {
  storageKey: string;
  children: ReactNode;
}) {
  const bKey = `r2-bookmarks:${storageKey}`;
  const aKey = `r2-addr:${storageKey}`;

  const [addr, setAddr] = useState(() => loadJson<string>(aKey, ""));
  const [showBytes, setShowBytes] = useState(false);

  const historyRef = useRef<HistoryEntry[]>([]);
  const idxRef = useRef(-1);
  const navigating = useRef(false);
  const [, tick] = useState(0);

  const seek = useCallback(
    (a: string, label?: string) => {
      setAddr(a);
      localStorage.setItem(aKey, JSON.stringify(a));

      if (!navigating.current) {
        historyRef.current = historyRef.current.slice(0, idxRef.current + 1);
        historyRef.current.push({ addr: a, label: label ?? a });
        idxRef.current = historyRef.current.length - 1;
        tick((t) => t + 1);
      }
    },
    [aKey],
  );

  const back = useCallback(() => {
    if (idxRef.current <= 0) return;
    idxRef.current--;
    navigating.current = true;
    const entry = historyRef.current[idxRef.current];
    setAddr(entry.addr);
    localStorage.setItem(aKey, JSON.stringify(entry.addr));
    navigating.current = false;
    tick((t) => t + 1);
  }, [aKey]);

  const forward = useCallback(() => {
    if (idxRef.current >= historyRef.current.length - 1) return;
    idxRef.current++;
    navigating.current = true;
    const entry = historyRef.current[idxRef.current];
    setAddr(entry.addr);
    localStorage.setItem(aKey, JSON.stringify(entry.addr));
    navigating.current = false;
    tick((t) => t + 1);
  }, [aKey]);

  const [bookmarks, setBookmarks] = useState<Bookmark[]>(() =>
    loadJson(bKey, []),
  );

  const addBookmark = useCallback(
    (b: Bookmark) => {
      setBookmarks((prev) => {
        const next = prev.filter((x) => x.addr !== b.addr).concat(b);
        localStorage.setItem(bKey, JSON.stringify(next));
        return next;
      });
    },
    [bKey],
  );

  const removeBookmark = useCallback(
    (a: string) => {
      setBookmarks((prev) => {
        const next = prev.filter((x) => x.addr !== a);
        localStorage.setItem(bKey, JSON.stringify(next));
        return next;
      });
    },
    [bKey],
  );

  const value = useMemo<R2ContextType>(
    () => ({
      addr,
      seek,
      history: historyRef.current,
      historyIdx: idxRef.current,
      back,
      forward,
      bookmarks,
      addBookmark,
      removeBookmark,
      showBytes,
      setShowBytes,
    }),
    [
      addr,
      seek,
      back,
      forward,
      bookmarks,
      addBookmark,
      removeBookmark,
      showBytes,
    ],
  );

  return <R2Ctx.Provider value={value}>{children}</R2Ctx.Provider>;
}

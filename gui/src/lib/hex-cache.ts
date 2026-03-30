export const PAGE_SIZE = 64 * 1024; // 64KB
const MAX_PAGES = 32;

type FetchFn = (offset: number, length: number) => Promise<ArrayBuffer | null>;

interface CachedPage {
  data: Uint8Array;
  lastAccess: number;
}

export class PageCache {
  readonly fileSize: number;
  readonly totalPages: number;
  private pages = new Map<number, CachedPage>();
  private inflight = new Map<number, Promise<void>>();
  private fetchFn: FetchFn;
  private tick = 0;

  version = 0;

  constructor(fileSize: number, fetchFn: FetchFn) {
    this.fileSize = fileSize;
    this.totalPages = Math.ceil(fileSize / PAGE_SIZE);
    this.fetchFn = fetchFn;
  }

  get loadedCount() {
    return this.pages.size;
  }

  pageFor(offset: number): number {
    return Math.floor(offset / PAGE_SIZE);
  }

  get(offset: number, length: number): Uint8Array | null {
    const pi = this.pageFor(offset);
    const page = this.pages.get(pi);
    if (!page) return null;
    page.lastAccess = ++this.tick;
    const start = offset - pi * PAGE_SIZE;
    const end = Math.min(start + length, page.data.length);
    return page.data.subarray(start, end);
  }

  async fetch(pageIndex: number): Promise<void> {
    if (this.pages.has(pageIndex)) return;
    if (this.inflight.has(pageIndex)) return this.inflight.get(pageIndex);

    const p = (async () => {
      const offset = pageIndex * PAGE_SIZE;
      const length = Math.min(PAGE_SIZE, this.fileSize - offset);
      const buf = await this.fetchFn(offset, length);
      this.inflight.delete(pageIndex);
      if (!buf) return;
      this.evict();
      this.pages.set(pageIndex, {
        data: new Uint8Array(buf),
        lastAccess: ++this.tick,
      });
      this.version++;
    })();

    this.inflight.set(pageIndex, p);
    return p;
  }

  prefetch(indices: number[]) {
    for (const i of indices) {
      if (i >= 0 && i < this.totalPages) this.fetch(i);
    }
  }

  private evict() {
    while (this.pages.size >= MAX_PAGES) {
      let oldest = -1;
      let oldestTick = Infinity;
      for (const [idx, page] of this.pages) {
        if (page.lastAccess < oldestTick) {
          oldestTick = page.lastAccess;
          oldest = idx;
        }
      }
      if (oldest >= 0) this.pages.delete(oldest);
      else break;
    }
  }
}

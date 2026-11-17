import { useState, useCallback } from "react";

export type SortDir = "asc" | "desc" | null;

export interface SortState {
  key: string | null;
  dir: SortDir;
}

/**
 * Simple hook for managing sort state on table columns.
 * Clicking a column cycles: asc → desc → none → asc
 */
export function useSort(defaultKey: string | null = null, defaultDir: SortDir = null) {
  const [sort, setSort] = useState<SortState>({ key: defaultKey, dir: defaultDir });

  const toggleSort = useCallback((key: string) => {
    setSort((prev) => {
      if (prev.key !== key) return { key, dir: "asc" };
      if (prev.dir === "asc") return { key, dir: "desc" };
      return { key: null, dir: null };
    });
  }, []);

  /** Apply sort to a dataset. Generic compare; numbers compare numerically, strings alphabetically. */
  const applySort = useCallback(
    <T,>(items: T[], getValue: (item: T) => string | number): T[] => {
      if (!sort.key || !sort.dir) return items;
      const sorted = [...items];
      sorted.sort((a, b) => {
        const va = getValue(a);
        const vb = getValue(b);
        let cmp: number;
        if (typeof va === "number" && typeof vb === "number") {
          cmp = va - vb;
        } else {
          cmp = String(va).localeCompare(String(vb));
        }
        return sort.dir === "asc" ? cmp : -cmp;
      });
      return sorted;
    },
    [sort]
  );

  /** Render a sort indicator arrow for a column header */
  const SortIndicator = useCallback(
    ({ columnKey }: { columnKey: string }) => {
      if (sort.key !== columnKey) {
        return <span className="ml-1 text-slate-700 text-[10px]">↕</span>;
      }
      return (
        <span className="ml-1 text-cyan-400 text-[10px]">
          {sort.dir === "asc" ? "↑" : "↓"}
        </span>
      );
    },
    [sort]
  );

  return { sort, toggleSort, applySort, SortIndicator };
}

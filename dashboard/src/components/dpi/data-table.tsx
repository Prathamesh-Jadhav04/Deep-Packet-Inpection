'use client';

import { useRef, useMemo, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { cn } from '@/lib/utils';
import { ArrowUpDown } from 'lucide-react';

export interface ColumnDef<T> {
  key: keyof T | string;
  header: string;
  render?: (item: T) => React.ReactNode;
  className?: string;
  sortable?: boolean;
}

interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T>[];
  rowKey: (item: T) => string | number;
  onRowClick?: (item: T) => void;
  actionField?: (item: T) => 'FORWARD' | 'DROP' | string;
  height?: string;
}

export function DataTable<T>({
  data,
  columns,
  rowKey,
  onRowClick,
  actionField,
  height = '400px',
}: DataTableProps<T>) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Handle column header sorting
  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortOrder('asc');
    }
  };

  const sortedData = useMemo(() => {
    if (!sortKey) return data;
    const sorted = [...data];
    sorted.sort((a: any, b: any) => {
      const valA = a[sortKey] ?? '';
      const valB = b[sortKey] ?? '';

      if (typeof valA === 'number' && typeof valB === 'number') {
        return sortOrder === 'asc' ? valA - valB : valB - valA;
      }
      return sortOrder === 'asc'
        ? String(valA).localeCompare(String(valB))
        : String(valB).localeCompare(String(valA));
    });
    return sorted;
  }, [data, sortKey, sortOrder]);

  const rowVirtualizer = useVirtualizer({
    count: sortedData.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => 36, // 36px estimated row height
    overscan: 10,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();

  return (
    <div className="flex flex-col w-full border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--panel)]">
      <div className="w-full overflow-x-auto scrollbar-none">
        <div className="min-w-[800px] md:min-w-full flex flex-col w-full">
          {/* Header section (Sticky/Fixed) */}
          <div className="w-full bg-[var(--panel-soft)] border-b border-[var(--border)] select-none">
            <div className="flex items-center text-caption-mono text-[var(--text-muted)] font-semibold uppercase tracking-wider text-[11px] py-2 px-3">
              {columns.map((col) => (
                <div
                  key={String(col.key)}
                  onClick={() => col.sortable && handleSort(String(col.key))}
                  className={cn(
                    'flex-1 flex items-center gap-1 min-w-0 py-1 first:pl-2',
                    col.sortable && 'cursor-pointer hover:text-[var(--text)] transition-colors',
                    col.className
                  )}
                >
                  <span className="truncate">{col.header}</span>
                  {col.sortable && (
                    <ArrowUpDown className={cn(
                      'w-3 h-3 flex-shrink-0',
                      sortKey === col.key ? 'text-[var(--accent-blue)]' : 'text-gray-600'
                    )} />
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Scrollable container with virtualization */}
          <div
            ref={containerRef}
            className="w-full overflow-y-auto scrollbar-thin"
            style={{ height }}
          >
            {sortedData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-caption text-[var(--text-muted)] font-mono">
                No records to display
              </div>
            ) : (
              <div
                className="w-full relative"
                style={{ height: `${totalSize}px` }}
              >
                {virtualRows.map((virtualRow) => {
                  const item = sortedData[virtualRow.index];
                  const key = rowKey(item);
                  const action = actionField ? actionField(item) : 'FORWARD';

                  return (
                    <div
                      key={key}
                      onClick={() => onRowClick?.(item)}
                      className={cn(
                        'absolute top-0 left-0 w-full flex items-center py-2 pr-3 border-b border-[var(--border-subtle)] transition-all hover:bg-[var(--panel-hover)]',
                        onRowClick && 'cursor-pointer',
                        action === 'DROP'
                          ? 'border-l-[3px] border-l-[var(--accent-red)] bg-[var(--accent-red-soft)]/5 text-[var(--accent-red)] hover:bg-[var(--accent-red-soft)]/10 pl-[9px]'
                          : 'border-l-[3px] border-l-transparent text-[var(--text-secondary)] pl-[9px] hover:border-l-[var(--accent-blue)]/50'
                      )}
                      style={{
                        height: `${virtualRow.size}px`,
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                    >
                      {columns.map((col) => (
                        <div
                          key={String(col.key)}
                          className={cn(
                            'flex-1 min-w-0 truncate text-body-sm first:pl-2',
                            col.className
                          )}
                        >
                          {col.render ? col.render(item) : String((item as any)[col.key] ?? '')}
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

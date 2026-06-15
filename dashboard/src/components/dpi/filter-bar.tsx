'use client';

import { useState, useEffect, useCallback } from 'react';
import { Search, X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface FilterBarProps {
  placeholder?: string;
  onFilterChange: (value: string) => void;
  className?: string;
  debounceMs?: number;
}

export function FilterBar({ placeholder = 'Filter...', onFilterChange, className, debounceMs = 300 }: FilterBarProps) {
  const [value, setValue] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => {
      onFilterChange(value);
    }, debounceMs);
    return () => clearTimeout(timer);
  }, [value, debounceMs, onFilterChange]);

  const clear = useCallback(() => {
    setValue('');
    onFilterChange('');
  }, [onFilterChange]);

  return (
    <div className={cn('relative', className)}>
      <Search
        className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
        style={{ color: 'var(--text-muted)' }}
      />
      <input
        type="text"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={placeholder}
        className="w-full h-9 pl-9 pr-8 rounded-md text-body-sm outline-none transition-colors"
        style={{
          background: 'var(--panel-soft)',
          color: 'var(--text)',
          border: '1px solid var(--border)',
        }}
        aria-label="Filter"
      />
      {value && (
        <button
          onClick={clear}
          className="absolute right-2 top-1/2 -translate-y-1/2 w-5 h-5 rounded-full flex items-center justify-center hover:opacity-80 transition-opacity"
          style={{ background: 'var(--border)', color: 'var(--text-muted)' }}
          aria-label="Clear filter"
        >
          <X className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}

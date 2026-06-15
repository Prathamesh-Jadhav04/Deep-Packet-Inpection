'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { useDPIStore } from '@/store/dpi-store';
import type { ThemeMode } from '@/types/dpi';

interface ThemeProviderProps {
  children: ReactNode;
}

const ThemeContext = createContext<{ theme: ThemeMode; setTheme: (theme: ThemeMode) => void }>({
  theme: 'dark',
  setTheme: () => {},
});

export function ThemeProvider({ children }: ThemeProviderProps) {
  const { theme, setTheme } = useDPIStore();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    const root = document.documentElement;
    
    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
      
      const listener = (e: MediaQueryListEvent) => {
        root.setAttribute('data-theme', e.matches ? 'dark' : 'light');
      };
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      mediaQuery.addEventListener('change', listener);
      return () => mediaQuery.removeEventListener('change', listener);
    } else {
      root.setAttribute('data-theme', theme);
    }
  }, [theme, mounted]);

  if (!mounted) {
    return <div style={{ visibility: 'hidden' }}>{children}</div>;
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);

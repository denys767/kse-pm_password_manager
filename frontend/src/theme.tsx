import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';
type ThemeContextValue = { preference: ThemePreference; setPreference: (value: ThemePreference) => void };
const ThemeContext = createContext<ThemeContextValue | null>(null);
const storageKey = 'kse-pm-theme';

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [preference, setPreference] = useState<ThemePreference>(() => {
        const value = localStorage.getItem(storageKey);
        return value === 'light' || value === 'dark' ? value : 'system';
    });
    useEffect(() => { document.documentElement.dataset.theme = preference; localStorage.setItem(storageKey, preference); }, [preference]);
    const value = useMemo(() => ({ preference, setPreference }), [preference]);
    return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
    const value = useContext(ThemeContext);
    if (!value) throw new Error('useTheme must be used inside ThemeProvider');
    return value;
}

import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource/red-hat-text/400.css';
import '@fontsource/red-hat-text/500.css';
import '@fontsource/red-hat-text/600.css';
import '@fontsource/red-hat-text/700.css';
import App from './App';
import { I18nProvider } from './i18n';
import { ThemeProvider } from './theme';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        <ThemeProvider><I18nProvider><App /></I18nProvider></ThemeProvider>
    </React.StrictMode>,
);

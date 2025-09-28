import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const rootElement = document.getElementById('root');
if (!rootElement) {
    throw new Error("L'élément racine est introuvable dans le DOM.");
}

createRoot(rootElement).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
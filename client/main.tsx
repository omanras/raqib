import { render } from 'preact';
import { App } from './app.js';
import { applyLang, currentLang } from './i18n/index.js';
import { applyTheme, theme } from './theme.js';
import './styles/tokens.css';
import './styles/base.css';
import './styles/layout.css';
import './styles/components.css';

applyLang(currentLang());
applyTheme(theme.get());
const root = document.getElementById('app');
if (root) render(<App />, root);

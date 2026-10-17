import { render } from 'preact';
import { App } from './app.js';
import { applyLang, currentLang } from './i18n/index.js';
import './styles/tokens.css';
import './styles/base.css';

applyLang(currentLang());
const root = document.getElementById('app');
if (root) render(<App />, root);

import { render } from "preact";

export const APP_VERSION: string = __APP_VERSION__;

function App() {
  return (
    <main>
      <h1>Qayd</h1>
      <p>
        version <span data-testid="version">{APP_VERSION}</span>
      </p>
    </main>
  );
}

const root = document.getElementById("app");
if (root) {
  render(<App />, root);
}

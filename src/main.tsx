import { render } from "preact";
import { App } from "./ui/App";
import "./ui/styles.css";

export const APP_VERSION: string = __APP_VERSION__;

const root = document.getElementById("app");
if (root) {
  render(<App />, root);
}

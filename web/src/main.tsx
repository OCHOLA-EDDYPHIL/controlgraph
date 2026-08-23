import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { installGoogleOperatorIdentity } from "./googleOperatorIdentity";
import "./styles.css";

installGoogleOperatorIdentity(
  window.controlGraphOperatorConfig?.oauthClientAudience,
);

const rootElement = document.getElementById("root");

if (rootElement === null) {
  throw new Error("root element is missing");
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

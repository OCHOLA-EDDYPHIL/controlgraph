import React from "react";
import ReactDOM from "react-dom/client";

import { PublicReplayApp } from "./PublicReplayApp";
import "./replayStyles.css";

const root = document.getElementById("replay-root");

if (root === null) {
  throw new Error("PUBLIC_REPLAY_ROOT_MISSING");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <PublicReplayApp />
  </React.StrictMode>,
);

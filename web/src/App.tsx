type ReadinessItem = {
  readonly label: string;
  readonly detail: string;
  readonly ready: boolean;
};

const readiness: readonly ReadinessItem[] = [
  {
    label: "Epoch fence primitive",
    detail: "Exact-match authority validation is covered by backend tests.",
    ready: true,
  },
  {
    label: "Cloud Run adapter",
    detail: "No mutation-capable adapter is wired in this scaffold.",
    ready: false,
  },
  {
    label: "Infrastructure",
    detail: "Terraform validates contracts but creates no resources.",
    ready: false,
  },
];

function StatusPill({ ready }: Pick<ReadinessItem, "ready">) {
  return (
    <span className={ready ? "status status--ready" : "status status--held"}>
      <span className="status__dot" aria-hidden="true" />
      {ready ? "Ready" : "Held safe"}
    </span>
  );
}

export function App() {
  return (
    <div className="shell">
      <header className="masthead">
        <a className="brand" href="#top" aria-label="ControlGraph Canary home">
          <span className="brand__mark" aria-hidden="true">
            CG
          </span>
          <span>
            <strong>ControlGraph</strong>
            <small>Canary control plane</small>
          </span>
        </a>
        <span className="environment">Local scaffold</span>
      </header>

      <main id="top">
        <section className="hero" aria-labelledby="page-title">
          <div>
            <p className="eyebrow">Epoch-fenced by design</p>
            <h1 id="page-title">One active controller. Every epoch.</h1>
            <p className="lede">
              A deliberately narrow foundation for safe Cloud Run canaries. Stale
              authority fails closed before control-plane access is introduced.
            </p>
          </div>
          <div className="fence-card" aria-label="Epoch fence example">
            <span className="fence-card__label">Authority check</span>
            <div className="epoch-row">
              <span>Token</span>
              <strong>0042</strong>
            </div>
            <div className="epoch-row">
              <span>Current</span>
              <strong>0042</strong>
            </div>
            <div className="fence-card__result">
              <span aria-hidden="true">✓</span> Exact epoch match
            </div>
          </div>
        </section>

        <section className="readiness" aria-labelledby="readiness-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Scaffold posture</p>
              <h2 id="readiness-title">Safe defaults, visible gaps</h2>
            </div>
            <p>Nothing here deploys or mutates a cloud resource.</p>
          </div>

          <div className="readiness-grid">
            {readiness.map((item, index) => (
              <article className="readiness-card" key={item.label}>
                <span className="readiness-card__number">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <h3>{item.label}</h3>
                <p>{item.detail}</p>
                <StatusPill ready={item.ready} />
              </article>
            ))}
          </div>
        </section>
      </main>

      <footer>
        <span>ControlGraph Canary</span>
        <span>Read-only operator surface</span>
      </footer>
    </div>
  );
}

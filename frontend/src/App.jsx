import { NavLink, Outlet } from "react-router-dom";

export default function App() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">ForentisAI</span>
          <span className="brand-sub">Email Threat &amp; Forensic Intelligence</span>
        </div>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/analysis">Analyze email</NavLink>
        </nav>
      </header>
      <main className="content">
        <Outlet />
      </main>
      <footer className="footnote">
        Model outputs and risk scores are evidence and policy thresholds only — never a
        final security determination. Dataset metrics are synthetic/corpus-only.
      </footer>
    </div>
  );
}

import { Brand } from "@/components/brand/brand";

export function SiteHeader() {
  return (
    <header className="site-header section-frame">
      <Brand />
      <nav className="site-nav" aria-label="Main navigation">
        <a href="#principles">Principles</a>
        <a href="#about">About</a>
      </nav>
      <a className="header-note" href="#about">
        <span aria-hidden="true" />
        Platform foundation
      </a>
    </header>
  );
}

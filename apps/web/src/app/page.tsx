import { ArrowUpRight, Fingerprint, LockKeyhole, ScanEye } from "lucide-react";
import { SiteFooter } from "@/components/layout/site-footer";
import { SiteHeader } from "@/components/layout/site-header";

const principles = [
  {
    icon: LockKeyhole,
    title: "Privacy as a foundation",
    description:
      "Data minimization and clear handling boundaries are design constraints, not afterthoughts.",
  },
  {
    icon: ScanEye,
    title: "Clarity over black boxes",
    description:
      "The platform is being designed to make future risk assessments understandable and reviewable.",
  },
  {
    icon: Fingerprint,
    title: "Flexible intelligence",
    description:
      "The architecture is intended to support local and cloud inference without tying the product to one provider.",
  },
];

export default function HomePage() {
  return (
    <div className="site-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <SiteHeader />
      <main id="main-content">
        <section className="hero section-frame" aria-labelledby="hero-title">
          <div className="hero-copy">
            <p className="eyebrow">
              <span className="eyebrow-mark" aria-hidden="true" />
              A Meta Infinium platform
            </p>
            <h1 id="hero-title">
              Security intelligence,
              <span> with clarity.</span>
            </h1>
            <p className="hero-description">
              ThreatSentinel is a privacy-first cybersecurity intelligence platform in
              development—built toward a more considered way to understand digital risk.
            </p>
            <div className="hero-actions">
              <a className="button button-primary" href="#principles">
                Explore our principles
                <ArrowUpRight size={16} aria-hidden="true" />
              </a>
              <a className="text-link" href="#about">
                About the platform
              </a>
            </div>
            <p className="availability-note">
              <span aria-hidden="true" />
              Engineering foundation in progress
            </p>
          </div>
          <div className="hero-art" aria-hidden="true">
            <div className="orbit orbit-outer" />
            <div className="orbit orbit-inner" />
            <div className="orbit-core">
              <div className="core-glow" />
              <div className="core-mark">
                <ScanEye size={34} strokeWidth={1.35} />
              </div>
            </div>
            <div className="orbit-node node-top" />
            <div className="orbit-node node-side" />
            <div className="art-caption">
              <span className="caption-line" />
              <span>Built for thoughtful defense</span>
            </div>
          </div>
          <div className="hero-index" aria-hidden="true">
            <span>01</span>
            <span className="index-rule" />
            <span>FOUNDATION</span>
          </div>
        </section>

        <section
          className="principles-section section-frame"
          id="principles"
          aria-labelledby="principles-title"
        >
          <div className="section-heading">
            <div>
              <p className="eyebrow">The point of view</p>
              <h2 id="principles-title">Designed with intention.</h2>
            </div>
            <p className="section-intro">
              These are architectural principles guiding development—not claims about
              features currently available.
            </p>
          </div>
          <div className="principle-grid">
            {principles.map(({ icon: Icon, title, description }, index) => (
              <article className="principle-card" key={title}>
                <div className="card-topline">
                  <span className="card-icon">
                    <Icon size={18} strokeWidth={1.7} aria-hidden="true" />
                  </span>
                  <span className="card-index">0{index + 1}</span>
                </div>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="about-section section-frame" id="about" aria-labelledby="about-title">
          <div className="about-rule" />
          <p className="eyebrow">A considered beginning</p>
          <h2 id="about-title">A stronger signal starts with a stronger foundation.</h2>
          <div className="about-bottom">
            <p>
              ThreatSentinel is being developed by Meta Infinium for individuals,
              organizations, and developers. Core product capabilities are planned and are
              not yet available.
            </p>
            <span className="roadmap-label">
              <span aria-hidden="true" />
              Early foundation
            </span>
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}

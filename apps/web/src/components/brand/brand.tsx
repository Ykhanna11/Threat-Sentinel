import Link from "next/link";
import { ShieldCheck } from "lucide-react";

type BrandProps = {
  compact?: boolean;
};

export function Brand({ compact = false }: BrandProps) {
  return (
    <Link
      className={`brand${compact ? " brand-compact" : ""}`}
      href="/"
      aria-label="ThreatSentinel home"
    >
      <span className="brand-symbol">
        <ShieldCheck size={19} strokeWidth={1.7} aria-hidden="true" />
      </span>
      <span className="brand-wordmark">
        <span className="brand-name">ThreatSentinel</span>
        {!compact && <span className="brand-byline">by Meta Infinium</span>}
      </span>
    </Link>
  );
}

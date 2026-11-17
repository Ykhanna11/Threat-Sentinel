import { Brand } from "@/components/brand/brand";

export function SiteFooter() {
  return (
    <footer className="site-footer section-frame">
      <Brand compact />
      <p>Thoughtful security intelligence, built with privacy in mind.</p>
      <span>© {new Date().getFullYear()} Meta Infinium</span>
    </footer>
  );
}

import { Shield, Lock, Eye, Server } from 'lucide-react';

export const Footer = () => {
  return (
    <footer className="no-print border-t border-[hsl(var(--border))] bg-[hsl(var(--muted))]/30">
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
        <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="mb-4 flex items-center gap-2">
              <Shield className="h-5 w-5 text-brand-600" aria-hidden="true" />
              <span className="font-bold">SafeLink</span>
            </div>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              Defensive URL security analysis. Check links before you click.
            </p>
          </div>
          <div>
            <h3 className="mb-3 text-sm font-semibold">Product</h3>
            <ul className="space-y-2 text-sm text-[hsl(var(--muted-foreground))]">
              <li><a href="/#how-it-works" className="hover:text-[hsl(var(--foreground))]">How it works</a></li>
              <li><a href="/#checks" className="hover:text-[hsl(var(--foreground))]">Security checks</a></li>
              <li><a href="/#faq" className="hover:text-[hsl(var(--foreground))]">FAQ</a></li>
            </ul>
          </div>
          <div>
            <h3 className="mb-3 text-sm font-semibold">Privacy</h3>
            <ul className="space-y-2 text-sm text-[hsl(var(--muted-foreground))]">
              <li className="flex items-start gap-2">
                <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                URLs are not stored permanently
              </li>
              <li className="flex items-start gap-2">
                <Eye className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                No credentials are ever logged
              </li>
            </ul>
          </div>
          <div>
            <h3 className="mb-3 text-sm font-semibold">Security</h3>
            <ul className="space-y-2 text-sm text-[hsl(var(--muted-foreground))]">
              <li className="flex items-start gap-2">
                <Server className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                SSRF-protected scanning
              </li>
              <li>Rate-limited API</li>
              <li>No JavaScript execution</li>
            </ul>
          </div>
        </div>
        <div className="mt-8 border-t border-[hsl(var(--border))] pt-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
          <p>&copy; {new Date().getFullYear()} SafeLink. Security analysis is probabilistic — no URL can be guaranteed safe.</p>
        </div>
      </div>
    </footer>
  );
};

import Link from 'next/link';
import { Shield } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';

export const Header = () => {
  return (
    <header className="no-print sticky top-0 z-50 border-b border-[hsl(var(--border))]/50 bg-[hsl(var(--background))]/80 backdrop-blur-lg">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5 transition-opacity hover:opacity-80" aria-label="SafeLink home">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600 shadow-lg shadow-brand-600/30">
            <Shield className="h-5 w-5 text-white" aria-hidden="true" />
          </div>
          <span className="text-xl font-bold tracking-tight">SafeLink</span>
        </Link>
        <nav className="flex items-center gap-4" aria-label="Main navigation">
          <Link
            href="/#how-it-works"
            className="hidden text-sm text-[hsl(var(--muted-foreground))] transition-colors hover:text-[hsl(var(--foreground))] sm:block"
          >
            How it works
          </Link>
          <Link
            href="/#faq"
            className="hidden text-sm text-[hsl(var(--muted-foreground))] transition-colors hover:text-[hsl(var(--foreground))] sm:block"
          >
            FAQ
          </Link>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
};

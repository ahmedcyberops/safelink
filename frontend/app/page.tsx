import { URLScanner } from '@/components/URLScanner';
import {
  Shield, Globe, Lock, ArrowRight, Search, Fingerprint,
  Server, AlertTriangle, Eye, ChevronDown,
} from 'lucide-react';

const CHECKS = [
  { icon: Globe, title: 'URL Structure', desc: 'Analyze scheme, encoding, length, and suspicious patterns' },
  { icon: Fingerprint, title: 'Domain Analysis', desc: 'Check TLD, subdomains, homographs, and punycode' },
  { icon: Server, title: 'DNS Records', desc: 'Resolve A, AAAA, MX, NS, and CNAME records' },
  { icon: Lock, title: 'TLS/HTTPS', desc: 'Verify certificate validity, issuer, and expiration' },
  { icon: ArrowRight, title: 'Redirect Chain', desc: 'Follow and validate redirect destinations safely' },
  { icon: Search, title: 'Reputation', desc: 'Cross-reference with threat intelligence providers' },
  { icon: AlertTriangle, title: 'Phishing Heuristics', desc: 'Detect credential harvesting and suspicious patterns' },
  { icon: Eye, title: 'Typosquatting', desc: 'Identify domains impersonating well-known brands' },
];

const FAQ = [
  {
    q: 'Is SafeLink free to use?',
    a: 'Yes, SafeLink is free for basic URL scanning. Rate limits apply to prevent abuse.',
  },
  {
    q: 'Does SafeLink guarantee a URL is safe?',
    a: 'No. Security analysis is probabilistic. SafeLink provides risk indicators to help you make informed decisions, but no URL can be guaranteed safe.',
  },
  {
    q: 'What happens to URLs I submit?',
    a: 'URLs are processed server-side for analysis. They are retained temporarily (default 24 hours) and may be shared with reputation providers when enabled. We never store credentials or log sensitive headers.',
  },
  {
    q: 'Can I scan shortened URLs?',
    a: 'Yes, but shortened URLs are flagged as a risk indicator since they can hide the final destination. SafeLink follows redirects safely with SSRF protection.',
  },
  {
    q: 'Why might a scan fail?',
    a: 'Scans may fail if the URL is malformed, points to a private/internal network (blocked for security), or the destination is unreachable.',
  },
];

export default function HomePage() {
  return (
    <>
      {/* Hero */}
      <section className="gradient-bg relative overflow-hidden px-4 pb-20 pt-16 sm:px-6 sm:pt-24">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-brand-600/10 via-transparent to-transparent" aria-hidden="true" />
        <div className="relative mx-auto max-w-4xl text-center">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-brand-500/20 bg-brand-500/10 px-4 py-1.5 text-sm text-brand-400">
            <Shield className="h-4 w-4" aria-hidden="true" />
            Defensive URL Security Analysis
          </div>
          <h1 className="mb-4 text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
            Check a link before{' '}
            <span className="bg-gradient-to-r from-brand-400 to-brand-600 bg-clip-text text-transparent">
              you click it.
            </span>
          </h1>
          <p className="mx-auto mb-10 max-w-2xl text-lg text-[hsl(var(--muted-foreground))] sm:text-xl">
            Analyze suspicious URLs for phishing, malware, redirects, and other security risks.
          </p>
          <div className="flex justify-center">
            <URLScanner />
          </div>
        </div>
      </section>

      {/* Supported Checks */}
      <section id="checks" className="px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-6xl">
          <h2 className="mb-4 text-center text-3xl font-bold">Security Checks</h2>
          <p className="mx-auto mb-12 max-w-2xl text-center text-[hsl(var(--muted-foreground))]">
            Every URL is analyzed through multiple defensive security layers.
          </p>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {CHECKS.map(({ icon: Icon, title, desc }) => (
              <div
                key={title}
                className="glass-card group p-5 transition-all hover:border-brand-500/30 hover:shadow-lg hover:shadow-brand-500/5"
              >
                <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-brand-600/10 text-brand-500 transition-colors group-hover:bg-brand-600/20">
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </div>
                <h3 className="mb-1 font-semibold">{title}</h3>
                <p className="text-sm text-[hsl(var(--muted-foreground))]">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="border-y border-[hsl(var(--border))] bg-[hsl(var(--muted))]/20 px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-4xl">
          <h2 className="mb-12 text-center text-3xl font-bold">How it works</h2>
          <ol className="space-y-8">
            {[
              { step: '1', title: 'Submit a URL', desc: 'Paste any suspicious link into the scanner. Do not include passwords or sensitive tokens.' },
              { step: '2', title: 'Multi-layer analysis', desc: 'Our engine validates the URL, resolves DNS, checks TLS, follows redirects safely, and runs phishing heuristics.' },
              { step: '3', title: 'Risk scoring', desc: 'Findings are weighted and combined into a 0–100 risk score with clear explanations.' },
              { step: '4', title: 'Review the report', desc: 'Get a detailed security report with findings, technical details, and recommended actions.' },
            ].map(({ step, title, desc }) => (
              <li key={step} className="flex gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-600 text-sm font-bold text-white">
                  {step}
                </div>
                <div>
                  <h3 className="font-semibold">{title}</h3>
                  <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))]">{desc}</p>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* Privacy */}
      <section className="px-4 py-16 sm:px-6">
        <div className="mx-auto max-w-3xl text-center">
          <Lock className="mx-auto mb-4 h-8 w-8 text-brand-500" aria-hidden="true" />
          <h2 className="mb-3 text-2xl font-bold">Your Privacy Matters</h2>
          <p className="text-[hsl(var(--muted-foreground))]">
            URLs are processed server-side and retained temporarily. Third-party reputation providers may receive
            domain information when enabled. We never store credentials, log authorization headers, or log cookies.
            Do not submit passwords, private tokens, or sensitive URLs.
          </p>
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="border-t border-[hsl(var(--border))] px-4 py-20 sm:px-6">
        <div className="mx-auto max-w-3xl">
          <h2 className="mb-12 text-center text-3xl font-bold">Frequently Asked Questions</h2>
          <div className="space-y-4">
            {FAQ.map(({ q, a }) => (
              <details
                key={q}
                className="glass-card group p-5"
              >
                <summary className="flex cursor-pointer items-center justify-between font-medium marker:content-none">
                  {q}
                  <ChevronDown className="h-4 w-4 shrink-0 transition-transform group-open:rotate-180" aria-hidden="true" />
                </summary>
                <p className="mt-3 text-sm leading-relaxed text-[hsl(var(--muted-foreground))]">{a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}

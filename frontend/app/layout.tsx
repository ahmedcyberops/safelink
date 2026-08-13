import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { ThemeProvider } from '@/components/ThemeProvider';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'SafeLink — URL Security Scanner | Phishing Link Checker',
  description:
    'Check suspicious URLs for phishing, malware, redirects, and security risks. Free URL checker and link security analyzer. Analyze links before you click.',
  keywords: [
    'URL checker',
    'phishing link checker',
    'suspicious link checker',
    'malicious URL checker',
    'link security checker',
    'URL scanner',
    'safe link checker',
  ],
  openGraph: {
    title: 'SafeLink — Check a link before you click it',
    description:
      'Analyze suspicious URLs for phishing, malware, redirects, and other security risks.',
    type: 'website',
    siteName: 'SafeLink',
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </head>
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
        <ThemeProvider>
          <div className="flex min-h-screen flex-col">
            <Header />
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}

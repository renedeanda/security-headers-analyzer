import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Security Headers Analyzer - Protect Your Website',
  description: 'Analyze and improve your website\'s HTTP security headers. Get instant security recommendations for CSP, HSTS, X-Frame-Options and more.',
  keywords: ['security headers', 'HTTP security', 'CSP', 'HSTS', 'web security', 'security analysis', 'vulnerability scanner', 'website security'],
  authors: [{ name: 'MAKR Security' }],
  openGraph: {
    title: 'Security Headers Analyzer - Protect Your Website',
    description: 'Analyze and improve your website\'s HTTP security headers with instant recommendations',
    type: 'website',
    siteName: 'MAKR Security',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Security Headers Analyzer - Protect Your Website',
    description: 'Analyze and improve your website\'s HTTP security headers with instant recommendations',
  },
  robots: {
    index: true,
    follow: true,
  },
  metadataBase: new URL('https://security.makr.io'),
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.className} antialiased`}>
        {children}
      </body>
    </html>
  )
}
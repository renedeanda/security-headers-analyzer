import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Free Security Headers Analyzer - Test Your Website\'s HTTP Security | MAKR',
  description: 'Instantly analyze your website\'s HTTP security headers with our free online tool. Check CSP, HSTS, X-Frame-Options and get actionable security recommendations. Test against OWASP standards.',
  keywords: [
    // Primary keywords (high volume, competitive)
    'security headers analyzer',
    'http security headers test',
    'security headers checker',
    'website security scanner',

    // Long-tail keywords (lower volume, higher intent)
    'free security headers analyzer online',
    'http security headers scan tool',
    'content security policy checker',
    'hsts analyzer tool',
    'x-frame-options checker',
    'security headers grading tool',

    // Technical SEO keywords
    'CSP analyzer', 'HSTS checker', 'web security audit',
    'OWASP security headers', 'HTTP response headers',
    'website vulnerability scanner', 'security assessment tool',

    // Competitive keywords
    'securityheaders.com alternative', 'mozilla observatory alternative',
    'header guard alternative', 'security headers scan'
  ],
  authors: [{ name: 'MAKR Security', url: 'https://makr.io' }],
  creator: 'MAKR Security',
  publisher: 'MAKR Security',
  category: 'Web Security Tools',

  // Enhanced Open Graph
  openGraph: {
    title: 'Free Security Headers Analyzer - Test Your Website\'s HTTP Security',
    description: 'Instantly analyze your website\'s HTTP security headers. Get security grades and actionable recommendations to protect against XSS, clickjacking, and data breaches.',
    type: 'website',
    siteName: 'MAKR Security Headers Analyzer',
    url: 'https://security.makr.io',
    locale: 'en_US',
    images: [
      {
        url: 'https://security.makr.io/og-image.png',
        width: 1200,
        height: 630,
        alt: 'MAKR Security Headers Analyzer - Free HTTP Security Testing Tool',
        type: 'image/png'
      }
    ]
  },

  // Enhanced Twitter
  twitter: {
    card: 'summary_large_image',
    site: '@makr_security',
    creator: '@makr_security',
    title: 'Free Security Headers Analyzer - Test Your Website\'s HTTP Security',
    description: 'Instantly analyze HTTP security headers. Get security grades and recommendations to protect against XSS, clickjacking, and data breaches.',
    images: ['https://security.makr.io/twitter-image.png']
  },

  // Enhanced robots and indexing
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },

  // Additional metadata
  alternates: {
    canonical: 'https://security.makr.io',
    languages: {
      'en-US': 'https://security.makr.io',
    },
  },

  // Verification and analytics
  verification: {
    google: 'your-google-site-verification-code',
    yandex: 'your-yandex-verification-code',
    yahoo: 'your-yahoo-verification-code',
  },

  // App metadata
  applicationName: 'MAKR Security Headers Analyzer',
  referrer: 'origin-when-cross-origin',

  // Enhanced icons with PNG favicon
  icons: {
    icon: [
      { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
      { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
      { url: '/favicon.png', sizes: '48x48', type: 'image/png' }
    ],
    apple: [
      { url: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' }
    ],
    other: [
      { url: '/android-chrome-192x192.png', sizes: '192x192', type: 'image/png' },
      { url: '/android-chrome-512x512.png', sizes: '512x512', type: 'image/png' }
    ]
  },

  // Manifest
  manifest: '/site.webmanifest',

  metadataBase: new URL('https://security.makr.io'),

  // Additional schema.org structured data
  other: {
    'application-name': 'MAKR Security Headers Analyzer',
    'msapplication-TileColor': '#6366f1',
    'msapplication-config': '/browserconfig.xml',
    'theme-color': '#6366f1'
  }
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <head>
        {/* Structured Data for Enhanced SEO - Using safer approach */}
        <script
          type="application/ld+json"
          suppressHydrationWarning={true}
        >
          {`{
            "@context": "https://schema.org",
            "@type": "WebApplication",
            "name": "MAKR Security Headers Analyzer",
            "description": "Free online tool to analyze and test your website's HTTP security headers. Get security grades and actionable recommendations.",
            "url": "https://security.makr.io",
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Any",
            "offers": {
              "@type": "Offer",
              "price": "0",
              "priceCurrency": "USD"
            },
            "provider": {
              "@type": "Organization",
              "name": "MAKR Security",
              "url": "https://makr.io"
            },
            "featureList": [
              "HTTP Security Headers Analysis",
              "Content Security Policy (CSP) Testing",
              "HSTS Configuration Check",
              "X-Frame-Options Validation",
              "Security Grade Assessment",
              "OWASP Compliance Testing",
              "Actionable Security Recommendations"
            ]
          }`}
        </script>

        {/* Additional SEO meta tags */}
        <meta name="format-detection" content="telephone=no" />
        <meta name="geo.region" content="US" />
        <meta name="rating" content="general" />
        <meta name="distribution" content="global" />
        <meta name="revisit-after" content="1 day" />

        {/* Performance hints */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link rel="dns-prefetch" href="https://security.makr.io" />
      </head>
      <body className={`${inter.className} antialiased`}>
        {children}
      </body>
    </html>
  )
}
// Security header configuration
export const SECURITY_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection'
];

// Improved scoring model with better weights
export const HEADER_WEIGHTS = {
  'content-security-policy': 40,              // Most critical - XSS protection
  'strict-transport-security': 25,            // Critical - HTTPS security
  'x-frame-options': 15,                      // Important - clickjacking
  'content-security-policy-report-only': 8,  // Monitoring only
  'x-content-type-options': 6,               // MIME protection
  'referrer-policy': 4,                      // Privacy
  'permissions-policy': 2,                   // Modern features
  'x-xss-protection': 0                      // Legacy, mostly ignored
};

export const EXAMPLE_SITES = [
  'github.com',
  'google.com',
  'stackoverflow.com',
  'cloudflare.com',
  'stripe.com',
  'vercel.com',
  'netlify.com',
  'mozilla.org',
  'x.com',
  'facebook.com',
  'instagram.com',
  'openai.com',
  'anthropic.com',
  'perplexity.ai',
  'cursor.com',
  'notion.so',
  'figma.com',
  'discord.com',
  'youtube.com',
  'shopify.com'
];
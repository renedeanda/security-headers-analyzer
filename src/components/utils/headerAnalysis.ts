import { SecurityHeader, HeaderAnalysis } from './types';
import { SECURITY_HEADERS, HEADER_WEIGHTS } from './constants';

// Individual analysis functions with proper scoring
const analyzeCspHeader = (name: string, value?: string, isEnforcing: boolean = true): SecurityHeader => {
  if (!value) {
    return {
      name,
      value,
      status: 'missing',
      score: 0,
      severity: 'critical',
      explanation: 'Content Security Policy prevents XSS attacks by controlling resource loading.',
      recommendation: 'Add CSP header: "default-src \'self\'; script-src \'self\' \'nonce-{random}\'"'
    };
  }

  let score = 100;
  let status: 'secure' | 'weak' | 'missing' = 'secure';
  let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';

  // Major security issues
  if (value.includes("'unsafe-inline'")) {
    score -= 35;
    status = 'weak';
    severity = 'high';
  }
  if (value.includes("'unsafe-eval'")) {
    score -= 35;
    status = 'weak';
    severity = 'high';
  }
  if (value.includes('*') && !value.includes("'nonce-") && !value.includes("'sha256-")) {
    score -= 25;
    status = 'weak';
    severity = 'medium';
  }

  // Bonus for good practices
  if (value.includes("'strict-dynamic'")) score += 10;
  if (value.includes("'nonce-") || value.includes("'sha256-")) score += 10;

  // Report-only gets reduced score
  if (!isEnforcing) {
    score = Math.round(score * 0.6);
    severity = score < 50 ? 'medium' : 'low';
  }

  return {
    name,
    value,
    status,
    score: Math.max(0, Math.min(100, score)),
    severity,
    explanation: isEnforcing ? 'Enforces resource loading restrictions to prevent XSS attacks.' : 'Monitors CSP violations without blocking content.',
    recommendation: status === 'weak' ? 'Remove unsafe directives and use nonces or hashes' : undefined
  };
};

const analyzeHstsHeader = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Strict-Transport-Security',
      value,
      status: 'missing',
      score: 0,
      severity: 'high',
      explanation: 'HSTS forces HTTPS connections and prevents protocol downgrade attacks.',
      recommendation: 'Add HSTS: "max-age=31536000; includeSubDomains; preload"'
    };
  }

  let score = 70; // Base score
  let status: 'secure' | 'weak' | 'missing' = 'secure';

  // Parse max-age
  const maxAgeMatch = value.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;

  if (maxAge < 86400) { // Less than 1 day
    score = 30;
    status = 'weak';
  } else if (maxAge >= 31536000) { // 1 year+
    score = 85;
  }

  if (value.includes('includeSubDomains')) score += 10;
  if (value.includes('preload')) score += 5;

  return {
    name: 'Strict-Transport-Security',
    value,
    status,
    score: Math.min(100, score),
    severity: status === 'weak' ? 'medium' : 'low',
    explanation: 'Enforces HTTPS and prevents man-in-the-middle attacks.',
    recommendation: status === 'weak' ? 'Increase max-age and add includeSubDomains' : undefined
  };
};

const analyzeFrameOptions = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'X-Frame-Options',
      value,
      status: 'missing',
      score: 0,
      severity: 'medium',
      explanation: 'Prevents clickjacking by controlling iframe embedding.',
      recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN'
    };
  }

  const lowerValue = value.toLowerCase();
  const isSecure = lowerValue === 'deny' || lowerValue === 'sameorigin';

  return {
    name: 'X-Frame-Options',
    value,
    status: isSecure ? 'secure' : 'weak',
    score: isSecure ? 100 : 40,
    severity: isSecure ? 'low' : 'medium',
    explanation: 'Controls whether your site can be framed by other sites.',
    recommendation: !isSecure ? 'Use DENY or SAMEORIGIN instead of permissive values' : undefined
  };
};

const analyzeContentTypeOptions = (value?: string): SecurityHeader => {
  const isSecure = value?.toLowerCase() === 'nosniff';

  return {
    name: 'X-Content-Type-Options',
    value,
    status: isSecure ? 'secure' : 'missing',
    score: isSecure ? 100 : 0,
    severity: isSecure ? 'low' : 'medium',
    explanation: 'Prevents MIME-sniffing attacks by enforcing declared content types.',
    recommendation: !isSecure ? 'Set X-Content-Type-Options: nosniff' : undefined
  };
};

const analyzeReferrerPolicy = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Referrer-Policy',
      value,
      status: 'missing',
      score: 0,
      severity: 'low',
      explanation: 'Controls referrer information sent with requests.',
      recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin'
    };
  }

  // Score based on privacy level
  let score = 100;
  let status: 'secure' | 'weak' | 'missing' = 'secure';

  const lowerValue = value.toLowerCase();
  if (lowerValue.includes('unsafe-url') || lowerValue === 'origin-when-cross-origin') {
    score = 60;
    status = 'weak';
  }

  return {
    name: 'Referrer-Policy',
    value,
    status,
    score,
    severity: status === 'weak' ? 'medium' : 'low',
    explanation: 'Controls how much referrer information is shared.',
    recommendation: status === 'weak' ? 'Use more restrictive policy like strict-origin-when-cross-origin' : undefined
  };
};

const analyzePermissionsPolicy = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Permissions-Policy',
      value,
      status: 'missing',
      score: 0,
      severity: 'low',
      explanation: 'Controls browser feature access to reduce attack surface.',
      recommendation: 'Add Permissions-Policy to restrict unused features'
    };
  }

  // Count restricted features
  const restrictedFeatures = ['camera', 'microphone', 'geolocation', 'payment'];
  const disabledCount = restrictedFeatures.filter(feature =>
    value.includes(`${feature}=()`)
  ).length;

  const score = 70 + (disabledCount / restrictedFeatures.length) * 30;

  return {
    name: 'Permissions-Policy',
    value,
    status: 'secure',
    score: Math.round(score),
    severity: 'low',
    explanation: 'Controls which browser features can be used.',
    recommendation: disabledCount < 2 ? 'Consider restricting more features' : undefined
  };
};

const analyzeXSSProtection = (value?: string, allHeaders?: Record<string, string>): SecurityHeader => {
  const hasCsp = allHeaders?.['content-security-policy'];

  if (!value) {
    return {
      name: 'X-XSS-Protection',
      value,
      status: hasCsp ? 'secure' : 'missing',
      score: hasCsp ? 90 : 0,
      severity: hasCsp ? 'low' : 'medium',
      explanation: 'Legacy XSS protection. CSP provides better security.',
      recommendation: hasCsp ? 'Not needed with CSP' : 'Add X-XSS-Protection: 1; mode=block or implement CSP'
    };
  }

  // X-XS-Protection: 0 is actually good if CSP is present
  if (value === '0' && hasCsp) {
    return {
      name: 'X-XSS-Protection',
      value,
      status: 'secure',
      score: 95,
      severity: 'low',
      explanation: 'Correctly disabled when CSP is present.',
      recommendation: undefined
    };
  }

  const isGoodConfig = value === '1; mode=block';

  return {
    name: 'X-XSS-Protection',
    value,
    status: isGoodConfig ? 'secure' : 'weak',
    score: isGoodConfig ? 85 : 50,
    severity: 'low',
    explanation: 'Legacy browser XSS filtering.',
    recommendation: !isGoodConfig ? 'Set to "1; mode=block" or implement CSP' : undefined
  };
};

const createMissingHeader = (name: string, severity: 'critical' | 'high' | 'medium' | 'low'): SecurityHeader => {
  return {
    name,
    value: undefined,
    status: 'missing',
    score: 0,
    severity,
    explanation: `${name} header is missing`,
    recommendation: `Implement ${name} for enhanced security`
  };
};

// Enhanced header analysis with better detection
export const analyzeHeader = (name: string, value?: string, allHeaders?: Record<string, string>): SecurityHeader => {
  const lowerName = name.toLowerCase();

  switch (lowerName) {
    case 'content-security-policy':
      return analyzeCspHeader('Content-Security-Policy', value, true);
    case 'content-security-policy-report-only':
      return analyzeCspHeader('Content-Security-Policy-Report-Only', value, false);
    case 'strict-transport-security':
      return analyzeHstsHeader(value);
    case 'x-frame-options':
      return analyzeFrameOptions(value);
    case 'x-content-type-options':
      return analyzeContentTypeOptions(value);
    case 'referrer-policy':
      return analyzeReferrerPolicy(value);
    case 'permissions-policy':
      return analyzePermissionsPolicy(value);
    case 'x-xss-protection':
      return analyzeXSSProtection(value, allHeaders);
    default:
      return createMissingHeader(name, 'medium');
  }
};

// ENHANCED HEADER ANALYSIS using our improved API route
export const analyzeHeadersReal = async (url: string): Promise<HeaderAnalysis> => {
  const response = await fetch(`/api/analyze-headers?url=${encodeURIComponent(url)}`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();

  if (!data.success) {
    throw new Error(data.error || 'Analysis failed');
  }

  // Process the raw headers into our security analysis
  const headers = SECURITY_HEADERS.map(headerName => {
    const value = data.headers[headerName];
    return analyzeHeader(headerName, value, data.headers);
  });

  // Calculate weighted score
  const totalPossibleScore = Object.values(HEADER_WEIGHTS).reduce((sum, weight) => sum + weight, 0);
  const actualScore = headers.reduce((sum, header) => {
    const headerName = header.name.toLowerCase().replace(/[^a-z-]/g, '');
    const weight = HEADER_WEIGHTS[headerName as keyof typeof HEADER_WEIGHTS] || 0;
    const weightedScore = (header.score / 100) * weight;
    return sum + weightedScore;
  }, 0);

  const overallScore = Math.round((actualScore / totalPossibleScore) * 100);

  return {
    url: data.url,
    headers,
    rawHeaders: data.headers,
    overallScore,
    timestamp: data.metadata.timestamp,
    method: 'enhanced-analysis',
    cached: data.cached || false,
    cacheAge: data.cacheAge || 0,
    responseInfo: data.responseInfo,
    metadata: data.metadata
  };
};
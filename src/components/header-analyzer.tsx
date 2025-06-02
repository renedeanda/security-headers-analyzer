import React, { useState, useEffect } from 'react';
import { Search, Globe, Shield, AlertTriangle, CheckCircle, XCircle, Clock, Info, ExternalLink, Zap, ArrowRight, TrendingUp, Award, Bug } from 'lucide-react';

// Types
interface SecurityHeader {
  name: string;
  value?: string;
  status: 'secure' | 'weak' | 'missing';
  score: number;
  explanation: string;
  recommendation?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
}

interface HeaderAnalysis {
  url: string;
  headers: SecurityHeader[];
  rawHeaders?: Record<string, string>;
  overallScore: number;
  timestamp: string;
  ipAddress?: string;
  method: string;
  responseInfo?: {
    status: number;
    statusText: string;
    redirected: boolean;
    finalUrl?: string;
  };
}

// Security header configuration
const SECURITY_HEADERS = [
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
const HEADER_WEIGHTS = {
  'content-security-policy': 40,              // Most critical - XSS protection
  'strict-transport-security': 25,            // Critical - HTTPS security
  'x-frame-options': 15,                      // Important - clickjacking
  'content-security-policy-report-only': 8,  // Monitoring only
  'x-content-type-options': 6,               // MIME protection
  'referrer-policy': 4,                      // Privacy
  'permissions-policy': 2,                   // Modern features
  'x-xss-protection': 0                      // Legacy, mostly ignored
};

// Enhanced CSP analysis with modern security practices
const analyzeCspHeader = (name: string, value?: string, isEnforcing: boolean = true): SecurityHeader => {
  if (!value) {
    return {
      name,
      value,
      status: 'missing',
      score: 0,
      severity: 'critical',
      explanation: 'Content Security Policy is the most effective defense against XSS attacks and code injection.',
      recommendation: 'Implement CSP immediately: start with "default-src \'self\'" and gradually add necessary sources'
    };
  }
  
  const baseMultiplier = isEnforcing ? 1.0 : 0.4; // Report-only gets less credit
  let cspScore = 100;
  let status: 'secure' | 'weak' | 'missing' = 'secure';
  let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';
  
  // Major security issues (each is a significant vulnerability)
  if (value.includes("'unsafe-inline'")) {
    cspScore -= 35; // Major vulnerability
    status = 'weak';
    severity = 'high';
  }
  if (value.includes("'unsafe-eval'")) {
    cspScore -= 35; // Major vulnerability
    status = 'weak';
    severity = 'high';
  }
  
  // Wildcard usage without proper restrictions
  if (value.includes("*") && !value.includes("'nonce-") && !value.includes("'sha256-")) {
    // Check if it's just data: or blob: which are safer
    if (!value.match(/\*\s*(;|$)/) && !value.includes("data: *") && !value.includes("blob: *")) {
      cspScore -= 25; // Significant issue
      status = 'weak';
      severity = 'medium';
    }
  }
  
  // Check for overly permissive policies
  if (value.includes("'unsafe-hashes'")) {
    cspScore -= 15;
    status = 'weak';
    severity = 'medium';
  }
  
  // Missing important directives
  const hasDefaultSrc = value.includes('default-src');
  const hasScriptSrc = value.includes('script-src');
  const hasStyleSrc = value.includes('style-src');
  const hasObjectSrc = value.includes('object-src');
  const hasBaseUri = value.includes('base-uri');
  
  if (!hasDefaultSrc && !hasScriptSrc) {
    cspScore -= 20; // No script control
    severity = 'high';
  }
  
  if (!hasObjectSrc) {
    cspScore -= 10; // Missing object-src can allow Flash/plugin attacks
  }
  
  if (!hasBaseUri) {
    cspScore -= 10; // Missing base-uri can allow base tag injection
  }
  
  // Bonus points for security best practices
  if (value.includes("'strict-dynamic'")) {
    cspScore += 15; // Modern CSP best practice
  }
  
  if (value.includes("'nonce-") || value.includes("'sha256-") || value.includes("'sha384-") || value.includes("'sha512-")) {
    cspScore += 10; // Using nonces or hashes
  }
  
  if (value.includes("upgrade-insecure-requests")) {
    cspScore += 5; // HTTPS enforcement
  }
  
  if (value.includes("block-all-mixed-content")) {
    cspScore += 5; // Blocks mixed content
  }
  
  // Apply base multiplier for report-only
  cspScore = Math.round(cspScore * baseMultiplier);
  
  let recommendation;
  if (status === 'weak') {
    const issues = [];
    if (value.includes("'unsafe-inline'")) issues.push("remove 'unsafe-inline'");
    if (value.includes("'unsafe-eval'")) issues.push("remove 'unsafe-eval'");
    if (value.includes("*") && !value.includes("'nonce-")) issues.push("replace wildcards with specific domains");
    
    recommendation = `Critical issues found: ${issues.join(', ')}. Use nonces or hashes for inline content.`;
  } else if (!isEnforcing) {
    recommendation = 'Upgrade from report-only to enforcing mode. Monitor violations first, then enforce.';
    severity = 'medium';
  } else if (cspScore < 90) {
    recommendation = 'Good CSP foundation. Consider adding strict-dynamic and removing any remaining unsafe directives.';
  }
  
  return {
    name,
    value,
    status,
    score: Math.max(0, Math.min(100, cspScore)),
    severity,
    explanation: isEnforcing 
      ? 'Controls which resources can load on your page. The most effective protection against XSS and code injection attacks.'
      : 'Monitors CSP violations without blocking content. Essential for testing policies before enforcement.',
    recommendation
  };
};

// Enhanced HSTS analysis
const analyzeHstsHeader = (value?: string): SecurityHeader => {
  if (!value) {
    return {
      name: 'Strict-Transport-Security',
      value,
      status: 'missing',
      score: 0,
      severity: 'high',
      explanation: 'Forces browsers to use HTTPS connections only. Critical for preventing man-in-the-middle attacks.',
      recommendation: 'Add HSTS header: "max-age=31536000; includeSubDomains; preload" (start with shorter max-age for testing)'
    };
  }
  
  let score = 70; // Base score for having HSTS
  let status: 'secure' | 'weak' | 'missing' = 'secure';
  let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';
  let recommendation;
  
  // Parse max-age
  const maxAgeMatch = value.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
  
  if (maxAge < 86400) { // Less than 1 day
    score = 30;
    status = 'weak';
    severity = 'medium';
    recommendation = 'Increase max-age to at least 1 year (31536000 seconds) for better security';
  } else if (maxAge < 2592000) { // Less than 30 days
    score = 50;
    status = 'weak';
    severity = 'medium';
    recommendation = 'Consider increasing max-age to 1 year (31536000 seconds)';
  } else if (maxAge >= 31536000) { // 1 year or more
    score = 85;
  }
  
  // Check for includeSubDomains
  if (value.includes('includeSubDomains')) {
    score += 10;
  } else {
    recommendation = (recommendation || '') + ' Add includeSubDomains to protect all subdomains.';
  }
  
  // Check for preload
  if (value.includes('preload')) {
    score += 5;
  } else if (score >= 80) {
    recommendation = (recommendation || '') + ' Consider adding preload directive and submitting to HSTS preload list.';
  }
  
  return {
    name: 'Strict-Transport-Security',
    value,
    status,
    score: Math.min(100, score),
    severity,
    explanation: 'Forces browsers to use HTTPS connections only. Prevents downgrade attacks and cookie hijacking.',
    recommendation
  };
};

// Enhanced header analysis with improved scoring
const analyzeHeader = (name: string, value?: string, allHeaders?: Record<string, string>): SecurityHeader => {
  const lowerName = name.toLowerCase();
  
  switch (lowerName) {
    case 'content-security-policy':
      return analyzeCspHeader('Content-Security-Policy', value, true);
    case 'content-security-policy-report-only':
      return analyzeCspHeader('Content-Security-Policy-Report-Only', value, false);
    case 'strict-transport-security':
      return analyzeHstsHeader(value);
    case 'x-frame-options':
      return {
        name: 'X-Frame-Options',
        value,
        status: value ? (value.toLowerCase() === 'deny' || value.toLowerCase() === 'sameorigin' ? 'secure' : 'weak') : 'missing',
        score: value ? (value.toLowerCase() === 'deny' || value.toLowerCase() === 'sameorigin' ? 100 : 40) : 0,
        severity: value ? (value.toLowerCase() === 'deny' || value.toLowerCase() === 'sameorigin' ? 'low' : 'medium') : 'medium',
        explanation: 'Prevents your site from being embedded in frames. Essential protection against clickjacking attacks.',
        recommendation: value ? (value.toLowerCase() === 'allowall' || value.toLowerCase() === 'allow-from' ? 'Use "DENY" or "SAMEORIGIN" instead of permissive values' : undefined) : 'Add X-Frame-Options: DENY (or SAMEORIGIN if you need to embed your own content)'
      };
    case 'x-content-type-options':
      return {
        name: 'X-Content-Type-Options',
        value,
        status: value?.toLowerCase() === 'nosniff' ? 'secure' : 'missing',
        score: value?.toLowerCase() === 'nosniff' ? 100 : 0,
        severity: value ? 'low' : 'medium',
        explanation: 'Prevents browsers from MIME-sniffing responses. Stops browsers from interpreting files as different content types.',
        recommendation: value?.toLowerCase() !== 'nosniff' ? 'Set X-Content-Type-Options: nosniff' : undefined
      };
    case 'referrer-policy':
      if (!value) {
        return {
          name: 'Referrer-Policy',
          value,
          status: 'missing',
          score: 0,
          severity: 'low',
          explanation: 'Controls referrer information sent with requests. Important for privacy and preventing data leakage.',
          recommendation: 'Set Referrer-Policy to "strict-origin-when-cross-origin" for good privacy without breaking functionality'
        };
      }
      
      // Score based on privacy level
      let score = 100;
      let status: 'secure' | 'weak' | 'missing' = 'secure';
      let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';
      
      const policy = value.toLowerCase();
      if (policy.includes('unsafe-url') || policy.includes('origin-when-cross-origin')) {
        score = 60;
        status = 'weak';
        severity = 'medium';
      } else if (policy.includes('no-referrer-when-downgrade')) {
        score = 70;
        status = 'weak';
      }
      
      return {
        name: 'Referrer-Policy',
        value,
        status,
        score,
        severity,
        explanation: 'Controls referrer information sent with requests. Protects user privacy and prevents sensitive URL data leakage.',
        recommendation: status === 'weak' ? 'Use "strict-origin-when-cross-origin" or "no-referrer" for better privacy' : undefined
      };

    case 'permissions-policy':
      if (!value) {
        return {
          name: 'Permissions-Policy',
          value,
          status: 'missing',
          score: 0,
          severity: 'low',
          explanation: 'Controls browser features and APIs. Reduces attack surface by restricting unnecessary capabilities.',
          recommendation: 'Add Permissions-Policy to disable unused features like "camera=(), microphone=(), geolocation=()"'
        };
      }
      
      // Score based on restrictiveness
      let permScore = 70; // Base score for having the header
      const restrictedFeatures = ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'bluetooth'];
      const disabledFeatures = restrictedFeatures.filter(feature => 
        value.includes(`${feature}=()`) || value.includes(`${feature}=none`)
      );
      
      permScore += (disabledFeatures.length / restrictedFeatures.length) * 30;
      
      return {
        name: 'Permissions-Policy',
        value,
        status: 'secure',
        score: Math.round(permScore),
        severity: 'low',
        explanation: 'Controls browser features and APIs. Modern replacement for Feature-Policy.',
        recommendation: disabledFeatures.length < 3 ? 'Consider restricting more features that your site doesn\'t use' : undefined
      };

    case 'x-xss-protection':
      const hasCsp = allHeaders?.['content-security-policy'] || allHeaders?.['content-security-policy-report-only'];
      
      if (!value) {
        return {
          name: 'X-XSS-Protection',
          value,
          status: hasCsp ? 'secure' : 'missing',
          score: hasCsp ? 95 : 0,
          severity: hasCsp ? 'low' : 'medium',
          explanation: 'Legacy XSS protection built into browsers. Largely superseded by Content Security Policy.',
          recommendation: hasCsp 
            ? 'Not needed with strong CSP - browser XSS protection is less effective than CSP'
            : 'Add X-XSS-Protection: 1; mode=block OR implement Content Security Policy (recommended)'
        };
      }
      
      if (value === '0') {
        return {
          name: 'X-XSS-Protection',
          value,
          status: hasCsp ? 'secure' : 'weak',
          score: hasCsp ? 100 : 20,
          severity: hasCsp ? 'low' : 'high',
          explanation: 'XSS protection explicitly disabled. Only safe when strong CSP is present.',
          recommendation: hasCsp 
            ? 'Correct approach - CSP provides better XSS protection than browser filters'
            : 'Dangerous without CSP! Either enable XSS protection or implement Content Security Policy'
        };
      }
      
      return {
        name: 'X-XSS-Protection',
        value,
        status: value === '1; mode=block' ? 'secure' : 'weak',
        score: value === '1; mode=block' ? 85 : 50,
        severity: 'low',
        explanation: 'Legacy XSS protection. Modern CSP is more effective and reliable.',
        recommendation: value !== '1; mode=block'
          ? 'Set to "1; mode=block" or implement Content Security Policy for better protection'
          : 'Consider upgrading to Content Security Policy for more comprehensive XSS protection'
      };

    default:
      return {
        name,
        value,
        status: 'missing',
        score: 0,
        severity: 'medium',
        explanation: 'Unknown security header',
        recommendation: undefined
      };
  }
};

// Get dynamic colors based on grade
const getGradeTheme = (score: number) => {
  if (score >= 90) {
    return {
      grade: 'A',
      bgGradient: 'from-emerald-50 via-green-50 to-teal-50',
      borderColor: 'border-emerald-200',
      circleColor: 'bg-gradient-to-br from-emerald-500 to-green-600',
      accentColor: 'text-emerald-700',
      badgeColor: 'bg-emerald-100 text-emerald-800',
      description: 'Excellent Security',
      icon: '🛡️'
    };
  } else if (score >= 80) {
    return {
      grade: 'B',
      bgGradient: 'from-blue-50 via-indigo-50 to-purple-50',
      borderColor: 'border-blue-200',
      circleColor: 'bg-gradient-to-br from-blue-500 to-indigo-600',
      accentColor: 'text-blue-700',
      badgeColor: 'bg-blue-100 text-blue-800',
      description: 'Good Security',
      icon: '🔒'
    };
  } else if (score >= 70) {
    return {
      grade: 'C',
      bgGradient: 'from-yellow-50 via-amber-50 to-orange-50',
      borderColor: 'border-yellow-200',
      circleColor: 'bg-gradient-to-br from-yellow-500 to-amber-600',
      accentColor: 'text-yellow-700',
      badgeColor: 'bg-yellow-100 text-yellow-800',
      description: 'Fair Security',
      icon: '⚠️'
    };
  } else if (score >= 60) {
    return {
      grade: 'D',
      bgGradient: 'from-orange-50 via-red-50 to-pink-50',
      borderColor: 'border-orange-200',
      circleColor: 'bg-gradient-to-br from-orange-500 to-red-500',
      accentColor: 'text-orange-700',
      badgeColor: 'bg-orange-100 text-orange-800',
      description: 'Poor Security',
      icon: '🔴'
    };
  } else {
    return {
      grade: 'F',
      bgGradient: 'from-red-50 via-rose-50 to-pink-50',
      borderColor: 'border-red-200',
      circleColor: 'bg-gradient-to-br from-red-500 to-rose-600',
      accentColor: 'text-red-700',
      badgeColor: 'bg-red-100 text-red-800',
      description: 'Critical Issues',
      icon: '🚨'
    };
  }
};

// REAL HEADER ANALYSIS using our Next.js API route
const analyzeHeadersReal = async (url: string): Promise<HeaderAnalysis> => {
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
    timestamp: data.timestamp,
    method: 'live-analysis',
    responseInfo: data.responseInfo
  };
};

// Helper function to safely extract hostname from URL
const getHostnameFromUrl = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    // If URL parsing fails, try to extract hostname manually
    const match = url.match(/^(?:https?:\/\/)?([^\/]+)/);
    return match ? match[1] : url;
  }
};

// UI Components
const GradeCircle = ({ score, theme }: { score: number; theme: any }) => {
  return (
    <div className={`w-24 h-24 rounded-2xl ${theme.circleColor} flex items-center justify-center shadow-xl border-4 border-white`}>
      <span className="text-4xl font-bold text-white">{theme.grade}</span>
    </div>
  );
};

const HeaderBadge = ({ header }: { header: SecurityHeader }) => {
  const getBadgeStyles = () => {
    switch (header.status) {
      case 'secure':
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
      case 'weak':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      case 'missing':
        return 'bg-red-100 text-red-800 border-red-200';
    }
  };

  const getIcon = () => {
    switch (header.status) {
      case 'secure':
        return <CheckCircle className="w-3 h-3 mr-1" />;
      case 'weak':
        return <AlertTriangle className="w-3 h-3 mr-1" />;
      case 'missing':
        return <XCircle className="w-3 h-3 mr-1" />;
    }
  };

  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border ${getBadgeStyles()}`}>
      {getIcon()}
      {header.name.replace('X-', '').replace('-', ' ')}
    </span>
  );
};

const SecurityCard = ({ header, theme }: { header: SecurityHeader; theme: any }) => {
  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className={`border-l-4 pl-6 py-4 ${
      header.status === 'secure' ? 'border-emerald-400 bg-emerald-50/30' : 
      header.status === 'weak' ? 'border-amber-400 bg-amber-50/30' : 
      'border-red-400 bg-red-50/30'
    } rounded-r-lg`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-semibold text-gray-900">{header.name}</h4>
        <div className="flex items-center gap-2">
          {header.severity && (
            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(header.severity)}`}>
              {header.severity.toUpperCase()}
            </span>
          )}
          <span className="text-sm font-medium text-gray-500">
            {header.score}/100
          </span>
        </div>
      </div>
      
      {header.value && (
        <div className="bg-gray-900 rounded-lg p-3 mb-3 overflow-x-auto">
          <code className="text-sm text-emerald-400 font-mono break-all">
            {header.value}
          </code>
        </div>
      )}
      
      <p className="text-sm text-gray-700 mb-2 leading-relaxed">
        {header.explanation}
      </p>
      
      {header.recommendation && (
        <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <p className="text-sm text-blue-800">
            <strong className="text-blue-900">💡 Recommendation:</strong> {header.recommendation}
          </p>
        </div>
      )}
    </div>
  );
};

// Main Component
export default function SecurityHeadersAnalyzer() {
  const [url, setUrl] = useState('');
  const [analysisResult, setAnalysisResult] = useState<HeaderAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [theme, setTheme] = useState(getGradeTheme(50));

  const exampleSites = [
    'github.com',
    'google.com',
    'stackoverflow.com',
    'microsoft.com',
    'cloudflare.com'
  ];

  // Update theme when analysis result changes
  useEffect(() => {
    if (analysisResult) {
      setTheme(getGradeTheme(analysisResult.overallScore));
    }
  }, [analysisResult]);

  const handleAnalyze = async () => {
    if (!url.trim()) {
      setError('Please enter a valid URL');
      return;
    }

    setLoading(true);
    setError('');
    setAnalysisResult(null);
    
    try {
      const result = await analyzeHeadersReal(url);
      setAnalysisResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze headers. Please check the URL and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleAnalyze();
    }
  };

  const formatUrl = (url: string): string => {
    return url.replace(/^https?:\/\//, '').replace(/\/$/, '');
  };

  const criticalIssues = analysisResult?.headers.filter(h => h.severity === 'critical' || (h.status === 'missing' && h.severity === 'high')).length || 0;
  const secureHeaders = analysisResult?.headers.filter(h => h.status === 'secure').length || 0;

  return (
    <div className={`min-h-screen bg-gradient-to-br ${theme.bgGradient} transition-all duration-1000`}>
      {/* Navigation */}
      <nav className="bg-white/80 backdrop-blur-sm border-b border-gray-200/50 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">Security Headers</h1>
                <p className="text-sm text-gray-600">by MAKR</p>
              </div>
            </div>
            
            {analysisResult && (
              <div className={`${theme.badgeColor} px-4 py-2 rounded-full flex items-center gap-2`}>
                <span className="text-xl">{theme.icon}</span>
                <span className="font-semibold">Grade {theme.grade}</span>
              </div>
            )}
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Hero Section */}
        {!analysisResult && (
          <div className="text-center mb-16">
            <div className="max-w-3xl mx-auto">
              <h1 className="text-5xl font-bold text-gray-900 mb-6 leading-tight">
                Analyze Your Website's
                <span className="bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent"> Security Headers</span>
              </h1>
              <p className="text-xl text-gray-600 mb-8 leading-relaxed">
                Get instant security analysis and actionable recommendations to protect your website from XSS, clickjacking, and other attacks.
              </p>

              {/* URL Input */}
              <div className="max-w-2xl mx-auto">
                <div className="flex gap-3 mb-6">
                  <div className="flex-1 relative">
                    <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                    <input
                      type="text"
                      placeholder="Enter website URL (e.g., example.com)"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyPress={handleKeyPress}
                      className="w-full pl-12 pr-4 h-14 text-lg border-2 border-gray-200 rounded-xl focus:border-indigo-500 focus:ring-4 focus:ring-indigo-200 outline-none transition-all bg-white/50 backdrop-blur-sm"
                    />
                  </div>
                  <button 
                    onClick={handleAnalyze} 
                    disabled={loading || !url.trim()}
                    className="h-14 px-8 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all flex items-center shadow-lg hover:shadow-xl"
                  >
                    {loading ? (
                      <>
                        <Search className="w-5 h-5 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="w-5 h-5 mr-2" />
                        Analyze
                      </>
                    )}
                  </button>
                </div>
                
                {/* Example URLs */}
                <div className="mb-8">
                  <p className="text-sm text-gray-600 mb-3">Popular examples:</p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {exampleSites.map((site) => (
                      <button
                        key={site}
                        onClick={() => setUrl(site)}
                        className="px-4 py-2 text-sm text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded-lg transition-colors border border-indigo-200"
                      >
                        {site}
                      </button>
                    ))}
                  </div>
                </div>

                {error && (
                  <div className="p-4 bg-red-50 border border-red-200 rounded-xl">
                    <p className="text-red-700 text-sm">{error}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {analysisResult && (
          <div className="space-y-8">
            {/* Compact URL Input for New Analysis */}
            <div className="mb-8">
              <div className="max-w-2xl mx-auto">
                <div className="flex gap-3">
                  <div className="flex-1 relative">
                    <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <input
                      type="text"
                      placeholder="Analyze another website..."
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyPress={handleKeyPress}
                      className="w-full pl-10 pr-4 h-12 border border-gray-300 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 outline-none transition-all bg-white/80 backdrop-blur-sm"
                    />
                  </div>
                  <button 
                    onClick={handleAnalyze} 
                    disabled={loading || !url.trim()}
                    className="h-12 px-6 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl transition-all flex items-center"
                  >
                    {loading ? (
                      <Search className="w-4 h-4 animate-spin" />
                    ) : (
                      <Search className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Security Score Card */}
            <div className={`bg-white/70 backdrop-blur-sm rounded-2xl border ${theme.borderColor} p-8 shadow-xl`}>
              <div className="mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Analysis</h2>
                <p className="text-gray-600">
                  <strong>{analysisResult.url}</strong>
                  {analysisResult.responseInfo?.redirected && analysisResult.responseInfo.finalUrl && (
                    <span className="text-sm text-gray-500 ml-2">
                      → redirected to {getHostnameFromUrl(analysisResult.responseInfo.finalUrl)}
                    </span>
                  )}
                </p>
                {analysisResult.responseInfo?.redirected && (
                  <p className="text-xs text-blue-600 mt-1">
                    Final URL: {analysisResult.responseInfo.finalUrl}
                  </p>
                )}
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
                {/* Grade Circle */}
                <div className="text-center">
                  <GradeCircle score={analysisResult.overallScore} theme={theme} />
                  <div className="mt-4">
                    <div className={`text-3xl font-bold ${theme.accentColor} mb-1`}>
                      {analysisResult.overallScore}/100
                    </div>
                    <div className="text-gray-600 font-medium">{theme.description}</div>
                  </div>
                </div>

                {/* Quick Stats */}
                <div className="lg:col-span-2 grid grid-cols-2 gap-6">
                  <div className="text-center p-4 bg-emerald-50 rounded-xl border border-emerald-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-emerald-100 rounded-xl mx-auto mb-3">
                      <CheckCircle className="w-6 h-6 text-emerald-600" />
                    </div>
                    <div className="text-2xl font-bold text-emerald-700 mb-1">{secureHeaders}</div>
                    <div className="text-sm text-emerald-600">Secure Headers</div>
                  </div>
                  
                  <div className="text-center p-4 bg-red-50 rounded-xl border border-red-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-red-100 rounded-xl mx-auto mb-3">
                      <Bug className="w-6 h-6 text-red-600" />
                    </div>
                    <div className="text-2xl font-bold text-red-700 mb-1">{criticalIssues}</div>
                    <div className="text-sm text-red-600">Critical Issues</div>
                  </div>
                  
                  <div className="text-center p-4 bg-blue-50 rounded-xl border border-blue-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-blue-100 rounded-xl mx-auto mb-3">
                      <TrendingUp className="w-6 h-6 text-blue-600" />
                    </div>
                    <div className="text-2xl font-bold text-blue-700 mb-1">{analysisResult.responseInfo?.status || 200}</div>
                    <div className="text-sm text-blue-600">HTTP Status</div>
                  </div>
                  
                  <div className="text-center p-4 bg-purple-50 rounded-xl border border-purple-200">
                    <div className="flex items-center justify-center w-12 h-12 bg-purple-100 rounded-xl mx-auto mb-3">
                      <Award className="w-6 h-6 text-purple-600" />
                    </div>
                    <div className="text-2xl font-bold text-purple-700 mb-1">{analysisResult.headers.length}</div>
                    <div className="text-sm text-purple-600">Headers Checked</div>
                  </div>
                </div>
              </div>

              {/* Header Status Pills */}
              <div className="mt-8 pt-6 border-t border-gray-200">
                <div className="flex flex-wrap gap-2">
                  {analysisResult.headers.map((header) => (
                    <HeaderBadge key={header.name} header={header} />
                  ))}
                </div>
              </div>
            </div>

            {/* Critical Issues Alert */}
            {criticalIssues > 0 && (
              <div className="bg-red-50 border-l-4 border-red-400 p-6 rounded-r-xl">
                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <XCircle className="h-5 w-5 text-red-400" />
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800">
                      {criticalIssues} Critical Security {criticalIssues === 1 ? 'Issue' : 'Issues'} Found
                    </h3>
                    <div className="mt-2 text-sm text-red-700">
                      <p>Your website has critical security vulnerabilities that should be addressed immediately to protect against attacks.</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Missing Headers */}
            {analysisResult.headers.filter(h => h.status === 'missing').length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                  <XCircle className="w-5 h-5 text-red-500" />
                  Missing Security Headers
                </h3>
                <div className="space-y-6">
                  {analysisResult.headers
                    .filter(header => header.status === 'missing')
                    .map((header) => (
                      <SecurityCard key={header.name} header={header} theme={theme} />
                    ))}
                </div>
              </div>
            )}

            {/* Weak Headers */}
            {analysisResult.headers.filter(h => h.status === 'weak').length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-500" />
                  Weak Security Headers
                </h3>
                <div className="space-y-6">
                  {analysisResult.headers
                    .filter(header => header.status === 'weak')
                    .map((header) => (
                      <SecurityCard key={header.name} header={header} theme={theme} />
                    ))}
                </div>
              </div>
            )}

            {/* Secure Headers */}
            {analysisResult.headers.filter(h => h.status === 'secure').length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6 flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-emerald-500" />
                  Secure Headers
                </h3>
                <div className="space-y-6">
                  {analysisResult.headers
                    .filter(header => header.status === 'secure')
                    .map((header) => (
                      <SecurityCard key={header.name} header={header} theme={theme} />
                    ))}
                </div>
              </div>
            )}

            {/* Raw Headers */}
            {analysisResult.rawHeaders && Object.keys(analysisResult.rawHeaders).length > 0 && (
              <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
                <h3 className="text-xl font-bold text-gray-900 mb-6">All HTTP Headers</h3>
                <div className="bg-gray-900 rounded-xl p-6 overflow-x-auto">
                  <div className="space-y-2">
                    {Object.entries(analysisResult.rawHeaders)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([key, value]) => (
                        <div key={key} className="flex">
                          <span className="text-blue-400 font-mono text-sm min-w-0 flex-shrink-0 mr-4">
                            {key}:
                          </span>
                          <span className="text-gray-300 font-mono text-sm break-all">
                            {value}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            )}

            {/* Security Resources */}
            <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-200 p-8 shadow-lg">
              <h3 className="text-xl font-bold text-gray-900 mb-6">Security Resources</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h4 className="font-semibold text-gray-800">Learn More</h4>
                  <div className="space-y-3">
                    <a 
                      href="https://owasp.org/www-project-secure-headers/" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-3 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors group"
                    >
                      <span className="text-blue-800 font-medium">OWASP Secure Headers</span>
                      <ExternalLink className="w-4 h-4 text-blue-600 group-hover:text-blue-800" />
                    </a>
                    <a 
                      href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-3 bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors group"
                    >
                      <span className="text-purple-800 font-medium">MDN HTTP Headers</span>
                      <ExternalLink className="w-4 h-4 text-purple-600 group-hover:text-purple-800" />
                    </a>
                    <a 
                      href="https://csp-evaluator.withgoogle.com/" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center justify-between p-3 bg-green-50 hover:bg-green-100 rounded-lg transition-colors group"
                    >
                      <span className="text-green-800 font-medium">CSP Evaluator</span>
                      <ExternalLink className="w-4 h-4 text-green-600 group-hover:text-green-800" />
                    </a>
                  </div>
                </div>
                
                <div className="space-y-4">
                  <h4 className="font-semibold text-gray-800">Common Fixes</h4>
                  <div className="space-y-3 text-sm text-gray-700">
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <strong>Nginx:</strong> Add headers to your server block
                    </div>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <strong>Apache:</strong> Use .htaccess or virtual host config
                    </div>
                    <div className="p-3 bg-gray-50 rounded-lg">
                      <strong>Cloudflare:</strong> Transform Rules or Workers
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                <div className="text-sm text-yellow-800">
                  <strong>💡 Pro Tip:</strong> Start with the highest severity issues first. Implementing Content Security Policy (CSP) provides the biggest security improvement.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-16 pt-8 border-t border-gray-200/50 text-center">
          <div className="text-sm text-gray-600">
            <p className="mb-2">Built by MAKR • Protecting websites with security best practices</p>
            <div className="flex justify-center gap-6">
              <a href="https://owasp.org" className="hover:text-gray-800 transition-colors">OWASP</a>
              <a href="https://mozilla.org/security" className="hover:text-gray-800 transition-colors">Mozilla Security</a>
              <a href="https://web.dev/secure" className="hover:text-gray-800 transition-colors">Web.dev Security</a>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
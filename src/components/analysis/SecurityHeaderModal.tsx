import React from 'react';
import { Shield, XCircle, Info, Zap, CheckCircle, AlertTriangle, ArrowRight } from 'lucide-react';
import { SecurityHeader } from '../utils/types';

interface SecurityHeaderModalProps {
  header: SecurityHeader | null;
  isOpen: boolean;
  onClose: () => void;
  isDark: boolean;
}

export const SecurityHeaderModal: React.FC<SecurityHeaderModalProps> = ({
  header,
  isOpen,
  onClose,
  isDark
}) => {
  if (!isOpen || !header) return null;

  const getDetailedExplanation = (headerName: string) => {
    const name = headerName.toLowerCase();

    switch (name) {
      case 'content-security-policy':
        return {
          purpose: "Content Security Policy (CSP) is a security layer that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
          howItWorks: "CSP works by specifying which resources (scripts, styles, images, etc.) are allowed to load and execute on your website. It uses directives like 'script-src', 'style-src', and 'img-src' to control resource origins.",
          bestPractices: [
            "Use 'strict-dynamic' for modern browsers",
            "Avoid 'unsafe-inline' and 'unsafe-eval'",
            "Use nonces or hashes for inline scripts/styles",
            "Start with a restrictive policy and gradually allow necessary sources",
            "Use 'Content-Security-Policy-Report-Only' for testing"
          ],
          commonIssues: [
            "Too permissive policies with wildcard (*) sources",
            "Using 'unsafe-inline' which defeats CSP's purpose",
            "Not including necessary domains for third-party resources"
          ]
        };

      case 'content-security-policy-report-only':
        return {
          purpose: "CSP Report-Only header allows you to test Content Security Policy without actually blocking resources. It only reports violations to a specified endpoint.",
          howItWorks: "This header works exactly like CSP but doesn't enforce the policy. Instead, it sends violation reports to help you understand what would be blocked if the policy were enforced.",
          bestPractices: [
            "Use this to test new CSP policies before enforcement",
            "Set up a reporting endpoint to collect violation data",
            "Gradually move from Report-Only to enforcing CSP",
            "Monitor reports to identify false positives"
          ],
          commonIssues: [
            "Forgetting to transition from Report-Only to enforcing",
            "Not setting up proper violation reporting",
            "Ignoring violation reports"
          ]
        };

      case 'strict-transport-security':
        return {
          purpose: "HTTP Strict Transport Security (HSTS) forces browsers to use secure HTTPS connections instead of HTTP, protecting against man-in-the-middle attacks and protocol downgrade attacks.",
          howItWorks: "Once a browser receives an HSTS header, it will automatically convert all HTTP requests to HTTPS for the specified domain and duration, even if the user types 'http://' in the address bar.",
          bestPractices: [
            "Use a max-age of at least 1 year (31536000 seconds)",
            "Include 'includeSubDomains' to protect subdomains",
            "Consider 'preload' directive for maximum security",
            "Ensure HTTPS is properly configured before enabling"
          ],
          commonIssues: [
            "Too short max-age values provide minimal protection",
            "Not including subdomains leaves them vulnerable",
            "Deploying HSTS without proper HTTPS setup"
          ]
        };

      default:
        return {
          purpose: "This security header helps protect your website from various attacks.",
          howItWorks: "Refer to the documentation for specific implementation details.",
          bestPractices: ["Follow security best practices", "Test thoroughly before deployment"],
          commonIssues: ["Misconfiguration", "Incomplete implementation"]
        };
    }
  };

  const details = getDetailedExplanation(header.name);

  const getStatusColor = (status: string) => {
    if (isDark) {
      switch (status) {
        case 'secure': return 'text-emerald-400 bg-emerald-900/30';
        case 'weak': return 'text-amber-400 bg-amber-900/30';
        case 'missing': return 'text-red-400 bg-red-900/30';
        default: return 'text-gray-400 bg-gray-800/50';
      }
    } else {
      switch (status) {
        case 'secure': return 'text-emerald-700 bg-emerald-50';
        case 'weak': return 'text-amber-700 bg-amber-50';
        case 'missing': return 'text-red-700 bg-red-50';
        default: return 'text-gray-700 bg-gray-50';
      }
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'secure': return 'Properly Configured';
      case 'weak': return 'Needs Improvement';
      case 'missing': return 'Not Implemented';
      default: return 'Unknown';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white dark:bg-gray-900 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto shadow-2xl border dark:border-gray-700">
        {/* Header */}
        <div className="sticky top-0 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 px-6 py-4 rounded-t-2xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">{header.name}</h2>
                <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(header.status)}`}>
                  {getStatusText(header.status)}
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
            >
              <XCircle className="w-5 h-5 text-gray-400" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Current Status */}
          <div className="bg-gray-50 dark:bg-gray-800 rounded-xl p-4">
            <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">Current Status</h3>
            <div className="flex items-center gap-4 mb-3">
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Score:</span>
              <span className="text-lg font-bold text-gray-900 dark:text-gray-100">{header.score}/100</span>
            </div>
            {header.value ? (
              <div className="bg-gray-900 dark:bg-gray-950 rounded-lg p-3 overflow-x-auto border dark:border-gray-700">
                <code className="text-sm text-emerald-400 font-mono break-all">
                  {header.value}
                </code>
              </div>
            ) : (
              <div className="bg-gray-200 dark:bg-gray-700 rounded-lg p-3 text-center">
                <span className="text-sm text-gray-600 dark:text-gray-400 italic">Header not present</span>
              </div>
            )}
          </div>

          {/* Purpose */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
              <Info className="w-4 h-4" />
              What is this header?
            </h3>
            <p className="text-gray-700 dark:text-gray-300 leading-relaxed">{details.purpose}</p>
          </div>

          {/* How it works */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
              <Zap className="w-4 h-4" />
              How it works
            </h3>
            <p className="text-gray-700 dark:text-gray-300 leading-relaxed">{details.howItWorks}</p>
          </div>

          {/* Best Practices */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-500" />
              Best Practices
            </h3>
            <ul className="space-y-2">
              {details.bestPractices.map((practice, index) => (
                <li key={index} className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full mt-2 flex-shrink-0"></div>
                  <span className="text-gray-700 dark:text-gray-300 text-sm">{practice}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Common Issues */}
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              Common Issues
            </h3>
            <ul className="space-y-2">
              {details.commonIssues.map((issue, index) => (
                <li key={index} className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 bg-amber-500 rounded-full mt-2 flex-shrink-0"></div>
                  <span className="text-gray-700 dark:text-gray-300 text-sm">{issue}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Current Recommendation */}
          {header.recommendation && (
            <div className="bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-700/50 rounded-xl p-4">
              <h3 className="font-semibold text-blue-900 dark:text-blue-200 mb-2 flex items-center gap-2">
                <ArrowRight className="w-4 h-4" />
                Recommendation for your site
              </h3>
              <p className="text-blue-800 dark:text-blue-300 text-sm leading-relaxed">{header.recommendation}</p>
            </div>
          )}

          {/* Implementation Guide */}
          <div className="bg-gray-50 dark:bg-gray-800 rounded-xl p-4">
            <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-3">Quick Implementation</h3>
            <div className="space-y-3 text-sm">
              <div className="bg-white dark:bg-gray-900 p-3 rounded-lg border dark:border-gray-700">
                <div className="font-medium text-gray-700 dark:text-gray-300 mb-1">Nginx:</div>
                <code className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                  add_header {header.name} "your-policy-here";
                </code>
              </div>
              <div className="bg-white dark:bg-gray-900 p-3 rounded-lg border dark:border-gray-700">
                <div className="font-medium text-gray-700 dark:text-gray-300 mb-1">Apache:</div>
                <code className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                  Header always set {header.name} "your-policy-here"
                </code>
              </div>
              <div className="bg-white dark:bg-gray-900 p-3 rounded-lg border dark:border-gray-700">
                <div className="font-medium text-gray-700 dark:text-gray-300 mb-1">Node.js/Express:</div>
                <code className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                  res.setHeader('{header.name}', 'your-policy-here');
                </code>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-4 bg-gray-50 dark:bg-gray-800 rounded-b-2xl">
          <div className="flex items-center justify-between">
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Learn more about security headers at OWASP.org
            </div>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm font-medium"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
import React from 'react';
import { Search, Globe, CheckCircle, Bug, TrendingUp, Award, XCircle, AlertTriangle, ExternalLink } from 'lucide-react';
import { HeaderAnalysis, SecurityHeader, GradeTheme } from '../utils/types';
import { getHostnameFromUrl } from '../utils/themeUtils';
import { GradeCircle } from '../ui/GradeCircle';
import { HeaderBadge } from '../ui/HeaderBadge';
import { SecurityCard } from '../ui/SecurityCard';
import { ServerInfoCard } from './ServerInfoCard';

interface ResultsSectionProps {
  analysisResult: HeaderAnalysis;
  theme: GradeTheme;
  isDark: boolean;
  url: string;
  setUrl: (url: string) => void;
  loading: boolean;
  onAnalyze: () => void;
  onKeyPress: (e: React.KeyboardEvent) => void;
  onHeaderClick: (header: SecurityHeader) => void;
}

export const ResultsSection: React.FC<ResultsSectionProps> = ({
  analysisResult,
  theme,
  isDark,
  url,
  setUrl,
  loading,
  onAnalyze,
  onKeyPress,
  onHeaderClick
}) => {
  const criticalIssues = analysisResult.headers.filter(h =>
    h.severity === 'critical' || (h.status === 'missing' && h.severity === 'high')
  ).length;
  const secureHeaders = analysisResult.headers.filter(h => h.status === 'secure').length;

  return (
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
                onKeyPress={onKeyPress}
                className="w-full pl-10 pr-4 h-12 border border-gray-300 dark:border-gray-600 rounded-xl focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 outline-none transition-all bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm text-gray-900 dark:text-gray-100 theme-transition"
              />
            </div>
            <button
              onClick={onAnalyze}
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
      <div className={`bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border ${theme.borderColor} p-8 shadow-xl theme-transition`}>
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">Security Analysis</h2>
          <p className="text-gray-600 dark:text-gray-400">
            <strong>{analysisResult.url}</strong>
            {analysisResult.responseInfo?.redirected && analysisResult.responseInfo.finalUrl && (
              <span className="text-sm text-gray-500 dark:text-gray-500 ml-2">
                → redirected to {getHostnameFromUrl(analysisResult.responseInfo.finalUrl)}
              </span>
            )}
          </p>
          {analysisResult.responseInfo?.redirected && (
            <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
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
              <div className="text-gray-600 dark:text-gray-400 font-medium">{theme.description}</div>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="lg:col-span-2 grid grid-cols-2 gap-6">
            <div className="text-center p-4 bg-emerald-50 dark:bg-emerald-900/20 rounded-xl border border-emerald-200 dark:border-emerald-700/50">
              <div className="flex items-center justify-center w-12 h-12 bg-emerald-100 dark:bg-emerald-800/50 rounded-xl mx-auto mb-3">
                <CheckCircle className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div className="text-2xl font-bold text-emerald-700 dark:text-emerald-400 mb-1">{secureHeaders}</div>
              <div className="text-sm text-emerald-600 dark:text-emerald-500">Secure Headers</div>
            </div>

            <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-xl border border-red-200 dark:border-red-700/50">
              <div className="flex items-center justify-center w-12 h-12 bg-red-100 dark:bg-red-800/50 rounded-xl mx-auto mb-3">
                <Bug className="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <div className="text-2xl font-bold text-red-700 dark:text-red-400 mb-1">{criticalIssues}</div>
              <div className="text-sm text-red-600 dark:text-red-500">Critical Issues</div>
            </div>

            <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-xl border border-blue-200 dark:border-blue-700/50">
              <div className="flex items-center justify-center w-12 h-12 bg-blue-100 dark:bg-blue-800/50 rounded-xl mx-auto mb-3">
                <TrendingUp className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div className="text-2xl font-bold text-blue-700 dark:text-blue-400 mb-1">{analysisResult.responseInfo?.status || 200}</div>
              <div className="text-sm text-blue-600 dark:text-blue-500">HTTP Status</div>
            </div>

            <div className="text-center p-4 bg-purple-50 dark:bg-purple-900/20 rounded-xl border border-purple-200 dark:border-purple-700/50">
              <div className="flex items-center justify-center w-12 h-12 bg-purple-100 dark:bg-purple-800/50 rounded-xl mx-auto mb-3">
                <Award className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div className="text-2xl font-bold text-purple-700 dark:text-purple-400 mb-1">{analysisResult.headers.length}</div>
              <div className="text-sm text-purple-600 dark:text-purple-500">Headers Checked</div>
            </div>
          </div>
        </div>

        {/* Header Status Pills */}
        <div className="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
          <div className="flex flex-wrap gap-2">
            {analysisResult.headers.map((header) => (
              <HeaderBadge
                key={header.name}
                header={header}
                onClick={() => onHeaderClick(header)}
                isDark={isDark}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Server Information Card */}
      <ServerInfoCard analysisResult={analysisResult} isDark={isDark} />

      {/* Critical Issues Alert */}
      {criticalIssues > 0 && (
        <div className="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-400 dark:border-red-600 p-6 rounded-r-xl">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <XCircle className="h-5 w-5 text-red-400" />
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800 dark:text-red-300">
                {criticalIssues} Critical Security {criticalIssues === 1 ? 'Issue' : 'Issues'} Found
              </h3>
              <div className="mt-2 text-sm text-red-700 dark:text-red-400">
                <p>Your website has critical security vulnerabilities that should be addressed immediately to protect against attacks.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Missing Headers */}
      {analysisResult.headers.filter(h => h.status === 'missing').length > 0 && (
        <div className="bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border border-gray-200 dark:border-gray-700 p-8 shadow-lg">
          <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6 flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-500" />
            Missing Security Headers
          </h3>
          <div className="space-y-6">
            {analysisResult.headers
              .filter(header => header.status === 'missing')
              .map((header) => (
                <SecurityCard key={header.name} header={header} theme={theme} isDark={isDark} />
              ))}
          </div>
        </div>
      )}

      {/* Weak Headers */}
      {analysisResult.headers.filter(h => h.status === 'weak').length > 0 && (
        <div className="bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border border-gray-200 dark:border-gray-700 p-8 shadow-lg">
          <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            Weak Security Headers
          </h3>
          <div className="space-y-6">
            {analysisResult.headers
              .filter(header => header.status === 'weak')
              .map((header) => (
                <SecurityCard key={header.name} header={header} theme={theme} isDark={isDark} />
              ))}
          </div>
        </div>
      )}

      {/* Secure Headers */}
      {analysisResult.headers.filter(h => h.status === 'secure').length > 0 && (
        <div className="bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border border-gray-200 dark:border-gray-700 p-8 shadow-lg">
          <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6 flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-emerald-500" />
            Secure Headers
          </h3>
          <div className="space-y-6">
            {analysisResult.headers
              .filter(header => header.status === 'secure')
              .map((header) => (
                <SecurityCard key={header.name} header={header} theme={theme} isDark={isDark} />
              ))}
          </div>
        </div>
      )}

      {/* Raw Headers */}
      {analysisResult.rawHeaders && Object.keys(analysisResult.rawHeaders).length > 0 && (
        <div className="bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border border-gray-200 dark:border-gray-700 p-8 shadow-lg">
          <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6">All HTTP Headers</h3>
          <div className="bg-gray-900 dark:bg-gray-950 rounded-xl p-6 overflow-x-auto border dark:border-gray-700">
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
      <div className="bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border border-gray-200 dark:border-gray-700 p-8 shadow-lg">
        <h3 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6">Security Resources</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h4 className="font-semibold text-gray-800 dark:text-gray-200">Learn More</h4>
            <div className="space-y-3">
              <a
                href="https://owasp.org/www-project-secure-headers/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-blue-50 dark:bg-blue-900/30 hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded-lg transition-colors group"
              >
                <span className="text-blue-800 dark:text-blue-300 font-medium">OWASP Secure Headers</span>
                <ExternalLink className="w-4 h-4 text-blue-600 dark:text-blue-400 group-hover:text-blue-800 dark:group-hover:text-blue-300" />
              </a>
              <a
                href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-purple-50 dark:bg-purple-900/30 hover:bg-purple-100 dark:hover:bg-purple-900/50 rounded-lg transition-colors group"
              >
                <span className="text-purple-800 dark:text-purple-300 font-medium">MDN HTTP Headers</span>
                <ExternalLink className="w-4 h-4 text-purple-600 dark:text-purple-400 group-hover:text-purple-800 dark:group-hover:text-purple-300" />
              </a>
              <a
                href="https://csp-evaluator.withgoogle.com/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-900/30 hover:bg-green-100 dark:hover:bg-green-900/50 rounded-lg transition-colors group"
              >
                <span className="text-green-800 dark:text-green-300 font-medium">CSP Evaluator</span>
                <ExternalLink className="w-4 h-4 text-green-600 dark:text-green-400 group-hover:text-green-800 dark:group-hover:text-green-300" />
              </a>
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="font-semibold text-gray-800 dark:text-gray-200">Common Fixes</h4>
            <div className="space-y-3 text-sm text-gray-700 dark:text-gray-300">
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <strong>Nginx:</strong> Add headers to your server block
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <strong>Apache:</strong> Use .htaccess or virtual host config
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <strong>Cloudflare:</strong> Transform Rules or Workers
              </div>
            </div>
          </div>
        </div>

        <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700/50 rounded">
          <div className="text-sm text-yellow-800 dark:text-yellow-300">
            <strong>💡 Pro Tip:</strong> Start with the highest severity issues first. Implementing Content Security Policy (CSP) provides the biggest security improvement.
          </div>
        </div>
      </div>
    </div>
  );
};
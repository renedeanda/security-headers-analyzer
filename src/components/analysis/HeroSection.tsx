import React from 'react';
import { Search, Globe } from 'lucide-react';
import { EXAMPLE_SITES } from '../utils/constants';

interface HeroSectionProps {
  url: string;
  setUrl: (url: string) => void;
  loading: boolean;
  error: string;
  onAnalyze: () => void;
  onKeyPress: (e: React.KeyboardEvent) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  url,
  setUrl,
  loading,
  error,
  onAnalyze,
  onKeyPress
}) => {
  return (
    <div className="text-center mb-16">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-5xl font-bold text-gray-900 dark:text-gray-100 mb-6 leading-tight">
          Analyze Your Website's
          <span className="bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent"> Security Headers</span>
        </h1>
        <p className="text-xl text-gray-600 dark:text-gray-400 mb-8 leading-relaxed">
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
                onKeyPress={onKeyPress}
                className="w-full pl-12 pr-4 h-14 text-lg border-2 border-gray-200 dark:border-gray-600 rounded-xl focus:border-indigo-500 focus:ring-4 focus:ring-indigo-200 outline-none transition-all bg-white/50 dark:bg-gray-800/50 backdrop-blur-sm text-gray-900 dark:text-gray-100 theme-transition"
              />
            </div>
            <button
              onClick={onAnalyze}
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
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">Popular examples:</p>
            <div className="flex flex-wrap justify-center gap-2">
              {EXAMPLE_SITES.map((site) => (
                <button
                  key={site}
                  onClick={() => setUrl(site)}
                  className="px-4 py-2 text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 rounded-lg transition-colors border border-indigo-200 dark:border-indigo-700/50"
                >
                  {site}
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-700/50 rounded-xl">
              <p className="text-red-700 dark:text-red-300 text-sm">{error}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
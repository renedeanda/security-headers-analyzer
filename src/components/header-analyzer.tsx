'use client'
import React, { useState, useEffect } from 'react';
import { HeaderAnalysis, SecurityHeader } from './utils/types';
import { getGradeTheme } from './utils/themeUtils';
import { analyzeHeadersReal } from './utils/headerAnalysis';
import { useTheme } from './hooks/useTheme';
import { Navigation } from './layout/Navigation';
import { HeroSection } from './analysis/HeroSection';
import { ResultsSection } from './analysis/ResultsSection';
import { SecurityHeaderModal } from './analysis/SecurityHeaderModal';

export default function SecurityHeadersAnalyzer() {
  const { isDark, toggleTheme } = useTheme();
  const [url, setUrl] = useState('');
  const [analysisResult, setAnalysisResult] = useState<HeaderAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [theme, setTheme] = useState(getGradeTheme(50, isDark));
  const [selectedHeader, setSelectedHeader] = useState<SecurityHeader | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  // Update theme when analysis result or dark mode changes
  useEffect(() => {
    if (analysisResult) {
      setTheme(getGradeTheme(analysisResult.overallScore, isDark));
    }
  }, [analysisResult, isDark]);

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

  const openModal = (header: SecurityHeader) => {
    setSelectedHeader(header);
    setModalOpen(true);
  };

  const closeModal = () => {
    setSelectedHeader(null);
    setModalOpen(false);
  };

  // Dark theme hero gradient - use grade-based gradient for results
  const heroGradient = isDark
    ? analysisResult
      ? theme.bgGradient  // Use grade-based gradient for results
      : 'from-gray-900 via-gray-800 to-gray-900'  // Simple gradient for hero
    : analysisResult
      ? theme.bgGradient
      : 'from-blue-50 via-indigo-50 to-purple-50';  // Light theme hero

  return (
    <div className={`min-h-screen bg-gradient-to-br ${heroGradient} transition-all duration-1000 theme-transition`}>
      {/* Navigation */}
      <Navigation
        isDark={isDark}
        toggleTheme={toggleTheme}
        theme={analysisResult ? theme : undefined}
        hasResult={!!analysisResult}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Hero Section */}
        {!analysisResult && (
          <HeroSection
            url={url}
            setUrl={setUrl}
            loading={loading}
            error={error}
            onAnalyze={handleAnalyze}
            onKeyPress={handleKeyPress}
          />
        )}

        {/* Results */}
        {analysisResult && (
          <ResultsSection
            analysisResult={analysisResult}
            theme={theme}
            isDark={isDark}
            url={url}
            setUrl={setUrl}
            loading={loading}
            onAnalyze={handleAnalyze}
            onKeyPress={handleKeyPress}
            onHeaderClick={openModal}
          />
        )}

        {/* Footer */}
        <footer className="mt-16 pt-8 border-t border-gray-200/50 dark:border-gray-700/50 text-center">
          <div className="text-sm text-gray-600 dark:text-gray-400">
            <p className="mb-2">Built by MAKR • Protecting websites with security best practices</p>
            <div className="flex justify-center gap-6">
              <a href="https://owasp.org" className="hover:text-gray-800 dark:hover:text-gray-200 transition-colors">OWASP</a>
              <a href="https://mozilla.org/security" className="hover:text-gray-800 dark:hover:text-gray-200 transition-colors">Mozilla Security</a>
              <a href="https://web.dev/secure" className="hover:text-gray-800 dark:hover:text-gray-200 transition-colors">Web.dev Security</a>
            </div>
          </div>
        </footer>

        {/* Header Details Modal */}
        <SecurityHeaderModal
          header={selectedHeader}
          isOpen={modalOpen}
          onClose={closeModal}
          isDark={isDark}
        />
      </div>
    </div>
  );
}
import React from 'react';
import { Shield } from 'lucide-react';
import { ThemeToggle } from '../ui/ThemeToggle';
import { GradeTheme } from '../utils/types';

interface NavigationProps {
  isDark: boolean;
  toggleTheme: () => void;
  theme?: GradeTheme;
  hasResult?: boolean;
}

export const Navigation: React.FC<NavigationProps> = ({
  isDark,
  toggleTheme,
  theme,
  hasResult
}) => {
  return (
    <nav className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm border-b border-gray-200/50 dark:border-gray-700/50 sticky top-0 z-10 theme-transition">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">Security Headers</h1>
              <p className="text-sm text-gray-600 dark:text-gray-400">by MAKR</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <ThemeToggle isDark={isDark} toggleTheme={toggleTheme} />
            {hasResult && theme && (
              <div className={`${theme.badgeColor} px-4 py-2 rounded-full flex items-center gap-2`}>
                <span className="text-xl">{theme.icon}</span>
                <span className="font-semibold">Grade {theme.grade}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};
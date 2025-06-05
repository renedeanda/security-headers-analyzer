import React from 'react';
import { SecurityHeader, GradeTheme } from '../utils/types';

interface SecurityCardProps {
  header: SecurityHeader;
  theme: GradeTheme;
  isDark: boolean;
}

export const SecurityCard: React.FC<SecurityCardProps> = ({ header, theme, isDark }) => {
  const getSeverityColor = (severity?: string) => {
    if (isDark) {
      switch (severity) {
        case 'critical': return 'text-red-400 bg-red-900/30';
        case 'high': return 'text-orange-400 bg-orange-900/30';
        case 'medium': return 'text-yellow-400 bg-yellow-900/30';
        case 'low': return 'text-green-400 bg-green-900/30';
        default: return 'text-gray-400 bg-gray-800/50';
      }
    } else {
      switch (severity) {
        case 'critical': return 'text-red-600 bg-red-50';
        case 'high': return 'text-orange-600 bg-orange-50';
        case 'medium': return 'text-yellow-600 bg-yellow-50';
        case 'low': return 'text-green-600 bg-green-50';
        default: return 'text-gray-600 bg-gray-50';
      }
    }
  };

  const getBorderColor = () => {
    if (isDark) {
      return header.status === 'secure' ? 'border-emerald-600/50 bg-emerald-900/10' :
        header.status === 'weak' ? 'border-amber-600/50 bg-amber-900/10' :
          'border-red-600/50 bg-red-900/10';
    } else {
      return header.status === 'secure' ? 'border-emerald-400 bg-emerald-50/30' :
        header.status === 'weak' ? 'border-amber-400 bg-amber-50/30' :
          'border-red-400 bg-red-50/30';
    }
  };

  return (
    <div className={`border-l-4 pl-6 py-4 ${getBorderColor()} rounded-r-lg`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-semibold text-gray-900 dark:text-gray-100">{header.name}</h4>
        <div className="flex items-center gap-2">
          {header.severity && (
            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(header.severity)}`}>
              {header.severity.toUpperCase()}
            </span>
          )}
          <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
            {header.score}/100
          </span>
        </div>
      </div>

      {header.value && (
        <div className="bg-gray-900 dark:bg-gray-950 rounded-lg p-3 mb-3 overflow-x-auto border dark:border-gray-700">
          <code className="text-sm text-emerald-400 font-mono break-all">
            {header.value}
          </code>
        </div>
      )}

      <p className="text-sm text-gray-700 dark:text-gray-300 mb-2 leading-relaxed">
        {header.explanation}
      </p>

      {header.recommendation && (
        <div className="mt-3 p-3 bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-700/50 rounded-lg">
          <p className="text-sm text-blue-800 dark:text-blue-300">
            <strong className="text-blue-900 dark:text-blue-200">💡 Recommendation:</strong> {header.recommendation}
          </p>
        </div>
      )}
    </div>
  );
};
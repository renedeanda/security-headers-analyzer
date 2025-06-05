import React from 'react';
import { CheckCircle, AlertTriangle, XCircle, Info } from 'lucide-react';
import { SecurityHeader } from '../utils/types';

interface HeaderBadgeProps {
  header: SecurityHeader;
  onClick?: () => void;
  isDark: boolean;
}

export const HeaderBadge: React.FC<HeaderBadgeProps> = ({ header, onClick, isDark }) => {
  const getBadgeStyles = () => {
    switch (header.status) {
      case 'secure':
        return isDark
          ? 'bg-emerald-900/30 text-emerald-400 border-emerald-700/50 hover:bg-emerald-800/40'
          : 'bg-emerald-100 text-emerald-800 border-emerald-200 hover:bg-emerald-200';
      case 'weak':
        return isDark
          ? 'bg-amber-900/30 text-amber-400 border-amber-700/50 hover:bg-amber-800/40'
          : 'bg-amber-100 text-amber-800 border-amber-200 hover:bg-amber-200';
      case 'missing':
        return isDark
          ? 'bg-red-900/30 text-red-400 border-red-700/50 hover:bg-red-800/40'
          : 'bg-red-100 text-red-800 border-red-200 hover:bg-red-200';
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
    <button
      onClick={onClick}
      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border transition-colors cursor-pointer ${getBadgeStyles()}`}
    >
      {getIcon()}
      {header.name.replace('X-', '').replace('-', ' ')}
      <Info className="w-3 h-3 ml-1 opacity-60" />
    </button>
  );
};
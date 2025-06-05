import { GradeTheme } from './types';

// Get dynamic colors based on grade
export const getGradeTheme = (score: number, isDark: boolean = false): GradeTheme => {
  if (score >= 90) {
    return {
      grade: 'A',
      bgGradient: isDark
        ? 'from-emerald-900 to-emerald-800'
        : 'from-emerald-50 via-green-50 to-teal-50',
      borderColor: isDark ? 'border-emerald-700/50' : 'border-emerald-200',
      circleColor: 'bg-gradient-to-br from-emerald-500 to-green-600',
      accentColor: isDark ? 'text-emerald-400' : 'text-emerald-700',
      badgeColor: isDark ? 'bg-emerald-900/30 text-emerald-400' : 'bg-emerald-100 text-emerald-800',
      description: 'Excellent Security',
      icon: '🛡️'
    };
  } else if (score >= 80) {
    return {
      grade: 'B',
      bgGradient: isDark
        ? 'from-blue-900 to-indigo-900'
        : 'from-blue-50 via-indigo-50 to-purple-50',
      borderColor: isDark ? 'border-blue-700/50' : 'border-blue-200',
      circleColor: 'bg-gradient-to-br from-blue-500 to-indigo-600',
      accentColor: isDark ? 'text-blue-400' : 'text-blue-700',
      badgeColor: isDark ? 'bg-blue-900/30 text-blue-400' : 'bg-blue-100 text-blue-800',
      description: 'Good Security',
      icon: '🔒'
    };
  } else if (score >= 70) {
    return {
      grade: 'C',
      bgGradient: isDark
        ? 'from-yellow-900 to-amber-900'
        : 'from-yellow-50 via-amber-50 to-orange-50',
      borderColor: isDark ? 'border-yellow-700/50' : 'border-yellow-200',
      circleColor: 'bg-gradient-to-br from-yellow-500 to-amber-600',
      accentColor: isDark ? 'text-yellow-400' : 'text-yellow-700',
      badgeColor: isDark ? 'bg-yellow-900/30 text-yellow-400' : 'bg-yellow-100 text-yellow-800',
      description: 'Fair Security',
      icon: '⚠️'
    };
  } else if (score >= 60) {
    return {
      grade: 'D',
      bgGradient: isDark
        ? 'from-orange-900 to-red-900'
        : 'from-orange-50 via-red-50 to-pink-50',
      borderColor: isDark ? 'border-orange-700/50' : 'border-orange-200',
      circleColor: 'bg-gradient-to-br from-orange-500 to-red-500',
      accentColor: isDark ? 'text-orange-400' : 'text-orange-700',
      badgeColor: isDark ? 'bg-orange-900/30 text-orange-400' : 'bg-orange-100 text-orange-800',
      description: 'Poor Security',
      icon: '🔴'
    };
  } else {
    return {
      grade: 'F',
      bgGradient: isDark
        ? 'from-red-900 to-rose-900'
        : 'from-red-50 via-rose-50 to-pink-50',
      borderColor: isDark ? 'border-red-700/50' : 'border-red-200',
      circleColor: 'bg-gradient-to-br from-red-500 to-rose-600',
      accentColor: isDark ? 'text-red-400' : 'text-red-700',
      badgeColor: isDark ? 'bg-red-900/30 text-red-400' : 'bg-red-100 text-red-800',
      description: 'Critical Issues',
      icon: '🚨'
    };
  }
};

// Helper function to safely extract hostname from URL
export const getHostnameFromUrl = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    const match = url.match(/^(?:https?:\/\/)?([^\/]+)/);
    return match ? match[1] : url;
  }
};

// Format IP address with location info
export const formatIPAddress = (ip: string) => {
  if (!ip || ip === 'Unknown') return 'Unknown';

  // Check if it's IPv6
  if (ip.includes(':')) {
    return `${ip} (IPv6)`;
  }

  return ip;
};
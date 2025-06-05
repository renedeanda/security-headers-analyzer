import React from 'react';
import { GradeTheme } from '../utils/types';

interface GradeCircleProps {
  score: number;
  theme: GradeTheme;
}

export const GradeCircle: React.FC<GradeCircleProps> = ({ score, theme }) => {
  return (
    <div className={`w-24 h-24 rounded-2xl ${theme.circleColor} flex items-center justify-center shadow-xl border-4 border-white dark:border-gray-800`}>
      <span className="text-4xl font-bold text-white">{theme.grade}</span>
    </div>
  );
};
import React from 'react';
import { Server, MapPin, Zap, Timer, Info, Wifi, Clock } from 'lucide-react';
import { HeaderAnalysis } from '../utils/types';
import { formatIPAddress } from '../utils/themeUtils';

interface ServerInfoCardProps {
  analysisResult: HeaderAnalysis;
  isDark: boolean;
}

export const ServerInfoCard: React.FC<ServerInfoCardProps> = ({ analysisResult, isDark }) => {
  const { responseInfo, metadata } = analysisResult;

  return (
    <div className="bg-white/70 dark:bg-gray-900/70 backdrop-blur-sm rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-lg">
      <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
        <Server className="w-5 h-5 text-gray-600 dark:text-gray-400" />
        Server Information
      </h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* IP Address with enhanced display */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <MapPin className="w-4 h-4" />
            <span className="font-medium">IP Address</span>
          </div>
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
            <div className="font-mono text-sm text-gray-900 dark:text-gray-100">
              {formatIPAddress(responseInfo?.ipAddress || metadata?.ipAddress || 'Unknown')}
            </div>
          </div>
        </div>

        {/* Server Software */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <Server className="w-4 h-4" />
            <span className="font-medium">Server</span>
          </div>
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
            <div className="text-sm text-gray-900 dark:text-gray-100">
              {responseInfo?.headers?.server || 'Unknown'}
            </div>
          </div>
        </div>

        {/* Powered By */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <Zap className="w-4 h-4" />
            <span className="font-medium">Powered By</span>
          </div>
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
            <div className="text-sm text-gray-900 dark:text-gray-100">
              {responseInfo?.headers?.poweredBy || 'Not disclosed'}
            </div>
          </div>
        </div>

        {/* Response Time */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <Timer className="w-4 h-4" />
            <span className="font-medium">Response Time</span>
          </div>
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
            <div className="text-sm text-gray-900 dark:text-gray-100">
              {metadata?.processingTime ? `${metadata.processingTime}ms` : 'Unknown'}
              {analysisResult.cached && (
                <span className="ml-2 text-xs text-blue-600 dark:text-blue-400">(cached {analysisResult.cacheAge}s ago)</span>
              )}
            </div>
          </div>
        </div>

        {/* Content Type */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <Info className="w-4 h-4" />
            <span className="font-medium">Content Type</span>
          </div>
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
            <div className="text-sm text-gray-900 dark:text-gray-100">
              {responseInfo?.headers?.contentType || 'Unknown'}
            </div>
          </div>
        </div>

        {/* Connection Status */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <Wifi className="w-4 h-4" />
            <span className="font-medium">Status</span>
          </div>
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${responseInfo?.status === 200 ? 'bg-green-500' :
                  responseInfo?.status && responseInfo.status < 400 ? 'bg-yellow-500' :
                    'bg-red-500'
                }`}></div>
              <span className="text-sm text-gray-900 dark:text-gray-100">
                {responseInfo?.status || 'Unknown'} {responseInfo?.statusText || ''}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Cache Status */}
      {analysisResult.cached && (
        <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-700/50 rounded-lg">
          <div className="flex items-center gap-2 text-sm text-blue-800 dark:text-blue-300">
            <Clock className="w-4 h-4" />
            <span>Results served from cache ({analysisResult.cacheAge} seconds old)</span>
          </div>
        </div>
      )}
    </div>
  );
};
// app/api/analyze-headers/route.js
// Improved security while maintaining functionality

import { NextResponse } from 'next/server';
import { headers } from 'next/headers';

// Simple in-memory rate limiting (for Vercel, consider Upstash Redis for production)
const rateLimitStore = new Map();

// Realistic browser configurations to avoid detection
const BROWSER_CONFIGS = [
  {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    acceptLanguage: 'en-US,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br',
    secChUa: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    secChUaPlatform: '"Windows"'
  },
  {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    acceptLanguage: 'en-US,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br',
    secChUa: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    secChUaPlatform: '"macOS"'
  },
  {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    acceptLanguage: 'en-US,en;q=0.5',
    acceptEncoding: 'gzip, deflate, br'
  }
];

// Comprehensive logging function
function logRequest(logData) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level: logData.level || 'INFO',
    ...logData
  };
  
  // Console log for Vercel logs (viewable in Vercel dashboard)
  console.log(`[${logEntry.level}] ${timestamp} - ${JSON.stringify(logEntry)}`);
  
  // Optional: Send to external logging service
  console.log(`🔗 Logging to external service: ${process.env.WEBHOOK_LOGGING_URL || 'not configured'}`);
  if (process.env.WEBHOOK_LOGGING_URL) {
    // Fire and forget webhook (don't await to avoid slowing down response)
    fetch(process.env.WEBHOOK_LOGGING_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(logEntry)
    }).catch(err => console.error('Webhook logging failed:', err));
  }
}

// Enhanced rate limiting with better cleanup
function checkRateLimit(clientIP, userAgent) {
  const now = Date.now();
  const minuteKey = `${clientIP}:${Math.floor(now / 60000)}`;
  
  // Periodic cleanup (every ~100 requests)
  if (Math.random() < 0.01) {
    const cutoff = now - 300000; // 5 minutes ago
    for (const [key, data] of rateLimitStore.entries()) {
      if (data.timestamp < cutoff) {
        rateLimitStore.delete(key);
      }
    }
  }

  const limitData = rateLimitStore.get(minuteKey) || { count: 0, timestamp: now };
  
  // More lenient rate limiting: 30 requests per minute
  if (limitData.count >= 30) {
    logRequest({
      level: 'WARN',
      event: 'rate_limit_exceeded',
      clientIP,
      userAgent,
      requestCount: limitData.count
    });
    throw new Error('Rate limit exceeded. Please wait a minute before trying again.');
  }

  rateLimitStore.set(minuteKey, { count: limitData.count + 1, timestamp: now });
}

// Get random browser config to avoid fingerprinting
function getRandomBrowserConfig() {
  return BROWSER_CONFIGS[Math.floor(Math.random() * BROWSER_CONFIGS.length)];
}

// Add random delay to avoid being flagged as bot
function randomDelay(min = 100, max = 500) {
  return new Promise(resolve => 
    setTimeout(resolve, Math.floor(Math.random() * (max - min + 1)) + min)
  );
}

// Enhanced but less restrictive URL validation
function validateAndNormalizeURL(url) {
  let targetUrl;
  try {
    // Handle different URL formats
    let urlToCheck = url.trim();
    
    // Add protocol if missing
    if (!urlToCheck.startsWith('http://') && !urlToCheck.startsWith('https://')) {
      urlToCheck = `https://${urlToCheck}`;
    }
    
    targetUrl = new URL(urlToCheck);
    
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      throw new Error('Only HTTP and HTTPS protocols are supported');
    }

    // Enhanced private network detection with more patterns
    const hostname = targetUrl.hostname.toLowerCase();
    const privatePatterns = [
      // IPv4 private ranges
      /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
      /^169\.254\./, /^0\.0\.0\.0$/, /^255\.255\.255\.255$/,
      // IPv6 patterns
      /^::1$/, /^::ffff:127\./, /^fc00:/, /^fd00:/, /^fe80:/,
      // Additional localhost variants
      /^localhost$/i, /^.*\.local$/i, /^.*\.localhost$/i,
      // Cloud metadata endpoints (AWS, GCP, Azure)
      /^169\.254\.169\.254$/, /^metadata\.google\.internal$/i,
      /^169\.254\.169\.254$/, /^100\.100\.100\.200$/
    ];
    
    const blockedHosts = [
      'localhost', 'local', '0.0.0.0', '127.0.0.1', 'broadcasthost',
      'ip6-localhost', 'ip6-loopback', 'metadata.google.internal',
      'instance-data', 'metadata'
    ];
    
    if (blockedHosts.includes(hostname) || privatePatterns.some(pattern => pattern.test(hostname))) {
      throw new Error('Cannot analyze private, local, or internal addresses');
    }

    // Basic hostname validation (less restrictive)
    if (hostname.includes('..') || hostname.length < 3) {
      throw new Error('Invalid hostname format');
    }

    // Check for suspicious ports
    const port = targetUrl.port;
    if (port && !['80', '443', '8080', '8443'].includes(port)) {
      logRequest({
        level: 'WARN',
        event: 'suspicious_port',
        hostname,
        port,
        url: targetUrl.toString()
      });
    }

    return targetUrl;

  } catch (error) {
    throw new Error(error.message.includes('Cannot analyze') ? error.message : 'Invalid URL format');
  }
}

export async function GET(request) {
  const startTime = Date.now();
  
  // Extract client information for logging
  const headersList = headers();
  const clientIP = headersList.get('x-forwarded-for')?.split(',')[0]?.trim() || 
                   headersList.get('x-real-ip') || 
                   headersList.get('cf-connecting-ip') || // Cloudflare
                   'unknown';
  const userAgent = headersList.get('user-agent') || 'unknown';
  const referer = headersList.get('referer') || 'direct';
  const country = headersList.get('cf-ipcountry') || 'unknown'; // Cloudflare country header
  
  try {
    // Rate limiting
    checkRateLimit(clientIP, userAgent);

    const { searchParams } = new URL(request.url);
    const url = searchParams.get('url');
    
    if (!url) {
      logRequest({
        level: 'WARN',
        event: 'missing_url_parameter',
        clientIP,
        userAgent,
        referer
      });
      return NextResponse.json(
        { error: 'URL parameter is required' },
        { status: 400 }
      );
    }

    // Validate URL
    const targetUrl = validateAndNormalizeURL(url);

    // Log successful request start
    logRequest({
      level: 'INFO',
      event: 'analysis_started',
      clientIP,
      userAgent,
      referer,
      country,
      targetUrl: targetUrl.toString(),
      targetHost: targetUrl.hostname
    });

    // Add small delay to appear more human-like
    await randomDelay(200, 800);

    console.log(`🔍 Analyzing: ${targetUrl.toString()} from ${clientIP} (${country})`);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000); // Reduced to 20 seconds
    
    let response;
    let lastError;
    const browserConfig = getRandomBrowserConfig();

    // Try multiple methods with realistic browser headers
    const methods = [
      { method: 'HEAD', followRedirects: true },
      { method: 'GET', followRedirects: true },
      { method: 'HEAD', followRedirects: false },
      { method: 'GET', followRedirects: false }
    ];

    for (const { method, followRedirects } of methods) {
      try {
        console.log(`🚀 Trying ${method} request ${followRedirects ? 'with' : 'without'} redirects...`);
        
        // Build realistic headers
        const headers = {
          'User-Agent': browserConfig.userAgent,
          'Accept': method === 'HEAD' 
            ? '*/*' 
            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'Accept-Language': browserConfig.acceptLanguage,
          'Accept-Encoding': browserConfig.acceptEncoding,
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'Upgrade-Insecure-Requests': '1',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          'DNT': '1'
        };

        // Add Chrome-specific headers if using Chrome UA
        if (browserConfig.secChUa) {
          headers['Sec-Ch-Ua'] = browserConfig.secChUa;
          headers['Sec-Ch-Ua-Mobile'] = '?0';
          headers['Sec-Ch-Ua-Platform'] = browserConfig.secChUaPlatform;
        }

        // Add referer for some enterprise sites that require it
        if (targetUrl.pathname !== '/') {
          headers['Referer'] = `${targetUrl.protocol}//${targetUrl.hostname}/`;
        }

        response = await fetch(targetUrl.toString(), {
          method,
          headers,
          signal: controller.signal,
          redirect: followRedirects ? 'follow' : 'manual',
          keepalive: false,
          mode: 'cors',
          credentials: 'omit'
        });

        // Check if we got a reasonable response
        if (response.ok || (response.status >= 300 && response.status < 400)) {
          console.log(`✅ Success with ${method} (${response.status})`);
          break;
        } else if (response.status === 403 || response.status === 429) {
          console.log(`⚠️ ${method} blocked (${response.status}), trying next method...`);
          await randomDelay(1000, 2000);
        }

      } catch (error) {
        lastError = error;
        console.log(`⚠️ ${method} failed: ${error.message}`);
        await randomDelay(300, 1000);
      }
    }

    clearTimeout(timeoutId);

    if (!response) {
      throw lastError || new Error('All request methods failed');
    }

    const processingTime = Date.now() - startTime;

    // Extract headers with better parsing
    const rawHeaders = {};
    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (rawHeaders[lowerKey]) {
        rawHeaders[lowerKey] = Array.isArray(rawHeaders[lowerKey]) 
          ? [...rawHeaders[lowerKey], value]
          : [rawHeaders[lowerKey], value];
      } else {
        rawHeaders[lowerKey] = value;
      }
    });

    // Get IP address (keep your existing logic)
    let ipAddress = 'Unknown';
    try {
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${targetUrl.hostname}&type=A`);
      if (dnsResponse.ok) {
        const dnsData = await dnsResponse.json();
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          ipAddress = dnsData.Answer[0].data;
        }
      }
    } catch (error) {
      console.log('Could not resolve IP:', error.message);
    }

    const responseInfo = {
      status: response.status,
      statusText: response.statusText,
      redirected: response.redirected,
      finalUrl: response.url,
      headers: {
        server: rawHeaders.server || 'Unknown',
        poweredBy: rawHeaders['x-powered-by'] || 'Unknown',
        contentType: rawHeaders['content-type'] || 'Unknown'
      }
    };

    // Log successful analysis
    logRequest({
      level: 'INFO',
      event: 'analysis_completed',
      clientIP,
      userAgent,
      referer,
      country,
      targetUrl: targetUrl.toString(),
      targetHost: targetUrl.hostname,
      responseStatus: response.status,
      responseTime: processingTime,
      headersFound: Object.keys(rawHeaders).length,
      serverInfo: rawHeaders.server,
      ipAddress: ipAddress,
      redirected: response.redirected,
      finalUrl: response.url
    });

    console.log(`📊 Found ${Object.keys(rawHeaders).length} headers for ${targetUrl.hostname} (${processingTime}ms)`);

    return NextResponse.json({
      success: true,
      url: targetUrl.toString(),
      finalUrl: response.url,
      headers: rawHeaders,
      responseInfo,
      metadata: {
        timestamp: new Date().toISOString(),
        processingTime,
        method: 'enterprise-compatible',
        ipAddress,
        userAgent: browserConfig.userAgent,
        requestMethod: response.url !== targetUrl.toString() ? 'redirected' : 'direct'
      }
    });

  } catch (error) {
    const processingTime = Date.now() - startTime;
    
    // Enhanced error categorization
    let errorMessage = error.message;
    let statusCode = 500;
    let category = 'unknown';

    if (error.name === 'AbortError') {
      errorMessage = 'Request timeout - website took too long to respond (20s)';
      statusCode = 408;
      category = 'timeout';
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('getaddrinfo')) {
      errorMessage = 'Website not found - please check the domain name';
      statusCode = 404;
      category = 'dns';
    } else if (error.message.includes('ECONNREFUSED')) {
      errorMessage = 'Connection refused - website may be down or blocking requests';
      statusCode = 503;
      category = 'connection';
    } else if (error.message.includes('certificate') || error.message.includes('CERT')) {
      errorMessage = 'SSL certificate error - website has certificate issues';
      statusCode = 526;
      category = 'ssl';
    } else if (error.message.includes('ECONNRESET')) {
      errorMessage = 'Connection reset - website dropped the connection';
      statusCode = 502;
      category = 'reset';
    } else if (error.message.includes('403')) {
      errorMessage = 'Access forbidden - website is blocking our requests';
      statusCode = 403;
      category = 'blocked';
    } else if (error.message.includes('429')) {
      errorMessage = 'Rate limited - website is temporarily blocking requests';
      statusCode = 429;
      category = 'rate-limit';
    } else if (error.message.includes('Rate limit')) {
      statusCode = 429;
      category = 'api-rate-limit';
    } else if (error.message.includes('Cannot analyze')) {
      statusCode = 403;
      category = 'blocked-url';
    }

    // Log error
    logRequest({
      level: 'ERROR',
      event: 'analysis_failed',
      clientIP,
      userAgent,
      referer,
      country,
      targetUrl: url,
      error: errorMessage,
      category,
      processingTime,
      originalError: error.message
    });

    console.error(`❌ Analysis failed after ${processingTime}ms:`, error.message);

    return NextResponse.json(
      { 
        success: false,
        error: errorMessage,
        category,
        metadata: {
          timestamp: new Date().toISOString(),
          processingTime
        },
        troubleshooting: category === 'blocked' ? [
          'The website may be using bot detection',
          'Try again in a few minutes',
          'Some enterprise sites block automated requests'
        ] : category === 'rate-limit' ? [
          'Website is temporarily blocking requests',
          'Wait a few minutes before trying again',
          'This is normal for high-security sites'
        ] : category === 'api-rate-limit' ? [
          'You are making requests too quickly',
          'Please wait a minute before trying again'
        ] : [
          'Check if the website is accessible in your browser',
          'Verify the URL is correct',
          'Some websites may block automated analysis'
        ]
      },
      { status: statusCode }
    );
  }
}
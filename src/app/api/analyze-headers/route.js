// app/api/analyze-headers/route.js
// Enterprise-compatible header analysis with anti-detection measures

import { NextResponse } from 'next/server';

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

export async function GET(request) {
  const startTime = Date.now();
  
  try {
    const { searchParams } = new URL(request.url);
    const url = searchParams.get('url');
    
    if (!url) {
      return NextResponse.json(
        { error: 'URL parameter is required' },
        { status: 400 }
      );
    }

    // Enhanced URL validation and normalization
    let targetUrl;
    try {
      // Handle different URL formats more intelligently
      let urlToCheck = url.trim();
      
      // Add protocol if missing
      if (!urlToCheck.startsWith('http://') && !urlToCheck.startsWith('https://')) {
        urlToCheck = `https://${urlToCheck}`;
      }
      
      targetUrl = new URL(urlToCheck);
      
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error('Only HTTP and HTTPS protocols are supported');
      }

      // Enhanced private network detection
      const hostname = targetUrl.hostname.toLowerCase();
      const privatePatterns = [
        /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
        /^169\.254\./, /^::1$/, /^fc00:/, /^fe80:/, /^0\.0\.0\.0$/
      ];
      
      const blockedHosts = ['localhost', 'local', '0.0.0.0', '127.0.0.1'];
      
      if (blockedHosts.includes(hostname) || privatePatterns.some(pattern => pattern.test(hostname))) {
        throw new Error('Cannot analyze private, local, or internal addresses');
      }

      // Validate hostname format
      if (hostname.includes('..') || hostname.includes('%') || hostname.length < 3) {
        throw new Error('Invalid hostname format');
      }

    } catch (error) {
      return NextResponse.json(
        { error: error.message.includes('Cannot analyze') ? error.message : 'Invalid URL format' },
        { status: 400 }
      );
    }

    // Add small delay to appear more human-like
    await randomDelay(200, 800);

    console.log(`🔍 Analyzing: ${targetUrl.toString()}`);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000); // 25 seconds for enterprise sites
    
    let response;
    let lastError;
    const browserConfig = getRandomBrowserConfig();

    // Try multiple methods with realistic browser headers
    const methods = [
      { method: 'HEAD', followRedirects: true },
      { method: 'GET', followRedirects: true },
      { method: 'HEAD', followRedirects: false }, // Some sites block HEAD with redirects
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
          // Additional options for enterprise compatibility
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
          // Add longer delay if we're being rate limited
          await randomDelay(1000, 2000);
        }

      } catch (error) {
        lastError = error;
        console.log(`⚠️ ${method} failed: ${error.message}`);
        
        // Add delay between attempts
        await randomDelay(300, 1000);
      }
    }

    clearTimeout(timeoutId);

    if (!response) {
      throw lastError || new Error('All request methods failed');
    }

    const processingTime = Date.now() - startTime;
    console.log(`✅ Analysis completed: ${response.status} ${response.statusText} (${processingTime}ms)`);

    // Extract headers with better parsing
    const rawHeaders = {};
    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      // Handle multiple headers with same name
      if (rawHeaders[lowerKey]) {
        rawHeaders[lowerKey] = Array.isArray(rawHeaders[lowerKey]) 
          ? [...rawHeaders[lowerKey], value]
          : [rawHeaders[lowerKey], value];
      } else {
        rawHeaders[lowerKey] = value;
      }
    });

    // Get IP address
    let ipAddress = 'Unknown';
    try {
      // Try to resolve IP address
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

    // Enhanced response info
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

    console.log(`📊 Found ${Object.keys(rawHeaders).length} headers for ${targetUrl.hostname}`);

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
    console.error(`❌ Analysis failed after ${processingTime}ms:`, error.message);
    
    // Enhanced error categorization
    let errorMessage = error.message;
    let statusCode = 500;
    let category = 'unknown';

    if (error.name === 'AbortError') {
      errorMessage = 'Request timeout - website took too long to respond (25s)';
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
    }

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
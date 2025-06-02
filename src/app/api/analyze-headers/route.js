// app/api/analyze-headers/route.js
// Fixed and improved version of your existing API route

import { NextResponse } from 'next/server';

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

    // Better URL validation
    let targetUrl;
    try {
      const urlToCheck = url.startsWith('http://') || url.startsWith('https://') 
        ? url 
        : `https://${url}`;
      
      targetUrl = new URL(urlToCheck);
      
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error('Only HTTP and HTTPS protocols are supported');
      }

      // Block private networks
      const hostname = targetUrl.hostname.toLowerCase();
      const privatePatterns = [
        /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
        /^169\.254\./, /^::1$/, /^fc00:/, /^fe80:/
      ];
      
      if (hostname === 'localhost' || privatePatterns.some(pattern => pattern.test(hostname))) {
        throw new Error('Cannot analyze private or local addresses');
      }

    } catch (error) {
      return NextResponse.json(
        { error: error.message.includes('Cannot analyze') ? error.message : 'Invalid URL format' },
        { status: 400 }
      );
    }

    // Improved fetch with fallbacks
    console.log(`🔍 Analyzing: ${targetUrl.toString()}`);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000); // 20 seconds
    
    let response;
    const methods = ['HEAD', 'GET'];
    let lastError;

    for (const method of methods) {
      try {
        response = await fetch(targetUrl.toString(), {
          method,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'DNT': '1'
          },
          signal: controller.signal,
          redirect: 'follow'
        });

        if (response.ok || response.status < 500) {
          break; // Success or client error (not server error)
        }
      } catch (error) {
        lastError = error;
        if (method === methods[methods.length - 1]) {
          throw error; // Last method failed
        }
      }
    }

    clearTimeout(timeoutId);

    if (!response) {
      throw lastError || new Error('All request methods failed');
    }

    console.log(`✅ Response: ${response.status} ${response.statusText}`);

    // Extract headers
    const rawHeaders = {};
    response.headers.forEach((value, key) => {
      rawHeaders[key.toLowerCase()] = value;
    });

    const processingTime = Date.now() - startTime;
    console.log(`📊 Analysis completed in ${processingTime}ms - Found ${Object.keys(rawHeaders).length} headers`);

    return NextResponse.json({
      success: true,
      url: targetUrl.toString(),
      finalUrl: response.url,
      headers: rawHeaders,
      responseInfo: {
        status: response.status,
        statusText: response.statusText,
        redirected: response.redirected,
        finalUrl: response.url
      },
      metadata: {
        timestamp: new Date().toISOString(),
        processingTime,
        method: 'enhanced-fetch'
      }
    });

  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error(`❌ Analysis failed after ${processingTime}ms:`, error.message);
    
    // Better error messages
    let errorMessage = error.message;
    let statusCode = 500;

    if (error.name === 'AbortError') {
      errorMessage = 'Request timeout - website took too long to respond';
      statusCode = 408;
    } else if (error.message.includes('ENOTFOUND')) {
      errorMessage = 'Website not found - please check the domain name';
      statusCode = 404;
    } else if (error.message.includes('ECONNREFUSED')) {
      errorMessage = 'Connection refused - website may be down';
      statusCode = 503;
    } else if (error.message.includes('certificate') || error.message.includes('CERT')) {
      errorMessage = 'SSL certificate error - website has certificate issues';
      statusCode = 526;
    }

    return NextResponse.json(
      { 
        success: false,
        error: errorMessage,
        metadata: {
          timestamp: new Date().toISOString(),
          processingTime
        }
      },
      { status: statusCode }
    );
  }
}
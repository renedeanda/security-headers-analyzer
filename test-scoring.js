// Quick test script to debug scoring logic
const mockGoogleHeaders = {
  'content-security-policy-report-only': "object-src 'none';base-uri 'self';script-src 'nonce-wLFFEp_ndwkymThsYLwIcw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp",
  'x-xss-protection': '0',
  'x-frame-options': 'SAMEORIGIN'
}

// Simulated scoring logic
const HEADER_WEIGHTS = {
  'content-security-policy': 30,
  'content-security-policy-report-only': 20,
  'strict-transport-security': 15,
  'x-frame-options': 15,
  'x-content-type-options': 10,
  'referrer-policy': 5,
  'x-xss-protection': 3,
  'permissions-policy': 2
}

// Simulate Google's expected scores
const headerScores = {
  'content-security-policy': 0, // Missing
  'content-security-policy-report-only': 60, // Present but report-only, has unsafe-inline/unsafe-eval
  'strict-transport-security': 60, // Missing but HTTPS (partial credit)
  'x-frame-options': 100, // SAMEORIGIN
  'x-content-type-options': 0, // Missing
  'referrer-policy': 0, // Missing
  'x-xss-protection': 95, // Disabled but CSP present
  'permissions-policy': 0 // Missing
}

const totalPossibleScore = Object.values(HEADER_WEIGHTS).reduce((sum, weight) => sum + weight, 0)
console.log('Total possible score:', totalPossibleScore)

const actualScore = Object.entries(headerScores).reduce((sum, [headerName, score]) => {
  const weight = HEADER_WEIGHTS[headerName] || 0
  const weightedScore = (score / 100) * weight
  console.log(`${headerName}: ${score}/100 * ${weight} = ${weightedScore}`)
  return sum + weightedScore
}, 0)

const overallScore = Math.round((actualScore / totalPossibleScore) * 100)
console.log(`\nActual score: ${actualScore}`)
console.log(`Overall score: ${overallScore}%`)

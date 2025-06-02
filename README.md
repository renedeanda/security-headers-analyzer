# Header Hero 🛡️

Header Hero is a web-based tool designed to help developers quickly understand and analyze HTTP security headers for any website. Built with Next.js 15, TypeScript, and Tailwind CSS.

## Features

✅ **Comprehensive Analysis**: Analyzes 8 key security headers including:
  - `Content-Security-Policy` & `Content-Security-Policy-Report-Only`
  - `Strict-Transport-Security`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `X-XSS-Protection`

✅ **Smart Scoring System**: 
  - Weighted scoring based on header importance
  - Contextual analysis (e.g., X-XSS-Protection considers CSP presence)
  - Handles CSP-Report-Only headers appropriately
  - Partial credit for HTTPS sites without HSTS

✅ **Security Scoring**: Each header is evaluated as:
  - 🟢 Secure
  - 🟡 Weak
  - 🔴 Missing

✅ **Educational**: Clear explanations and actionable recommendations for each header

✅ **Modern UI**: Responsive design with visual score indicators and example sites

## Recent Improvements (v1.1)

### Enhanced Scoring Logic
- **CSP-Report-Only Support**: Properly handles and scores Content-Security-Policy-Report-Only headers (60% of enforcing policy score)
- **Contextual X-XSS-Protection**: Smart scoring that gives high marks when XSS protection is disabled but CSP is present
- **Weighted Scoring**: Realistic scoring system that prioritizes critical headers (CSP: 30pts, HSTS: 15pts, etc.)
- **HTTPS Awareness**: Partial credit (60%) for sites using HTTPS even without explicit HSTS header

### Technical Improvements
- 10-second timeout for header fetching
- Enhanced CSP analysis with penalties for unsafe-inline/unsafe-eval
- Better error handling and user feedback
- Added Mozilla.org as example test site

## Getting Started

### Prerequisites

- Node.js (version 14 or later)
- npm (Node Package Manager)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/header-hero.git
   ```
2. Navigate to the project directory:
   ```
   cd header-hero
   ```
3. Install the dependencies:
   ```
   npm install
   ```

### Running the Application

To start the development server, run:
```
npm run dev
```
Open your browser and navigate to `http://localhost:3000` to access the application.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- Inspired by the need for better web security practices.
- Built with Next.js and Tailwind CSS for a modern web experience.
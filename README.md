# Security Headers Analyzer 🛡️

[![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3-38B2AC?logo=tailwind-css)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live Demo](https://img.shields.io/badge/Live-Demo-brightgreen?logo=vercel)](https://security.makr.io)

A modern, free web tool to analyze and grade your website's HTTP security headers. Get instant security assessments with actionable recommendations to protect against XSS, clickjacking, and other web vulnerabilities.

## 🚀 Live Demo

**Try it now**: [security.makr.io](https://security.makr.io)

Test with popular sites like GitHub, Google, Stripe, or enter your own domain for instant analysis!

## ✨ Features

### 🔍 **Comprehensive Security Analysis**
Analyzes **8 critical security headers** with intelligent scoring:

| Header | Weight | Purpose |
|--------|--------|---------|
| `Content-Security-Policy` | 30pts | Prevents XSS and code injection attacks |
| `Strict-Transport-Security` | 15pts | Enforces HTTPS connections |
| `X-Frame-Options` | 10pts | Protects against clickjacking |
| `X-Content-Type-Options` | 10pts | Prevents MIME-type sniffing |
| `Referrer-Policy` | 10pts | Controls referrer information leakage |
| `Permissions-Policy` | 10pts | Manages browser feature permissions |
| `X-XSS-Protection` | 10pts | Legacy XSS protection (context-aware) |
| `CSP-Report-Only` | 5pts | Monitors policy violations |

### 🎯 **Smart Scoring System**
- **Grade-based evaluation** (A+ to F) with visual indicators
- **Contextual analysis** (e.g., X-XSS-Protection scored intelligently when CSP is present)
- **Weighted scoring** prioritizing critical headers
- **HTTPS awareness** with partial credit for secure connections
- **CSP-Report-Only support** for gradual policy deployment

### 📊 **Visual Grade System**
- 🟢 **A/B Grades**: Excellent/Good security posture
- 🟡 **C/D Grades**: Fair/Poor security with improvement needed
- 🔴 **F Grade**: Critical security issues requiring immediate attention

### 🎓 **Educational Resources**
- **Clear explanations** for each security header
- **Actionable recommendations** with implementation examples
- **OWASP compliance** guidance
- **Best practices** for modern web security

### 🎨 **Modern User Experience**
- **Responsive design** optimized for all devices
- **Dark/Light theme** with smooth transitions
- **Real-time analysis** with progress indicators
- **Example sites** for quick testing (GitHub, Stripe, OpenAI, etc.)

## 🛠️ Tech Stack

- **Framework**: Next.js 15 with App Router
- **Language**: TypeScript for type safety
- **Styling**: Tailwind CSS with custom theme system
- **Icons**: Lucide React for modern iconography
- **Deployment**: Optimized for Vercel/Netlify

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm/yarn/pnpm

### Installation

```bash
# Clone the repository
git clone https://github.com/renedeanda/security-headers-analyzer.git

# Navigate to project directory
cd security-headers-analyzer

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the application.

### Build for Production

```bash
# Create optimized production build
npm run build

# Start production server
npm start
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Guidelines
- Follow TypeScript best practices
- Maintain existing code style and formatting
- Add tests for new features
- Update documentation as needed

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/renedeanda/security-headers-analyzer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/renedeanda/security-headers-analyzer/discussions)
- **Website**: [security.makr.io](https://security.makr.io)

---

<div align="center">

**Made with 💜 by [René DeAnda](https://renedeanda.com)**

</div>
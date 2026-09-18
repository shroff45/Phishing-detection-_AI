# PhishGuard — Chrome Web Store Listing

## Extension Name
PhishGuard — AI Phishing Shield

## Summary (132 chars max)
Real-time AI phishing detection. Blocks credential theft, brand spoofing,
and zero-day attacks before they reach you.

## Description
PhishGuard uses machine learning to protect you from phishing attacks
in real time. Unlike traditional blocklists that only catch known
threats, PhishGuard's AI analyzes every page you visit and detects
phishing attempts that have never been seen before.

### How It Works
- Analyzes URL patterns using a trained XGBoost model (runs locally)
- Scans page content for credential harvesting forms and suspicious code
- Detects brand impersonation through visual similarity analysis
- Blocks known threats via continuously updated threat intelligence feeds
- Warns you with a clear overlay before you enter credentials

### Privacy First
- All fast-path analysis runs entirely on your device
- No browsing history is ever collected or transmitted
- No screenshots or page images are ever sent — visual checks use a
  derived favicon hash and colour summary, never pixels
- URLs are only sent to our server when local analysis is inconclusive
  AND you explicitly enable this in settings
- Fully open source — inspect every line of code

### Features
✅ Real-time phishing detection (< 10ms for clear cases)
✅ AI-powered URL classification
✅ Visual brand impersonation detection
✅ Anti-evasion: catches Browser-in-the-Browser attacks
✅ Redirect chain analysis
✅ Automatic threat feed updates every 6 hours
✅ Works in incognito mode
✅ Zero tracking, zero ads, zero data collection

Built by students at VIT for public welfare.

## Category
Productivity

## Language
English

## Single Purpose Description (for Chrome review)
This extension detects phishing websites by analyzing URLs and page
content using machine learning, and warns users before they enter
credentials on malicious pages.

## Permission Justifications

| Permission | Justification |
|---|---|
| storage | Store cached scan results and user preferences locally |
| alarms | Schedule periodic threat feed updates (every 6 hours) |
| offscreen | Run ML model inference in a DOM-enabled offscreen document |
| declarativeNetRequest | Block known phishing domains at the network level |
| webNavigation | Detect page navigation events to trigger URL analysis |
| scripting | Inject content scripts for DOM analysis |
| tabs | Read the URL of the current tab for analysis and badge updates |
| host_permissions (http/https) | Analyze URLs on all websites the user visits |

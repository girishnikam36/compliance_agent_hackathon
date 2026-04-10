/**
 * test_samples/sample_04_typescript_frontend.ts
 * ===============================================
 * EXPLOIT CATEGORY : Frontend / Client-side PII Exposure + GDPR Art. 13, 17
 * SEVERITY PROFILE : 2 CRITICAL · 3 HIGH · 1 MEDIUM
 * REGULATIONS      : GDPR, CCPA, DPDPA
 * LANGUAGE         : TypeScript (React/browser)
 *
 * What this file simulates:
 *   A React TypeScript frontend service that stores PII client-side,
 *   exposes API keys in browser-accessible code, and implements a
 *   non-compliant cookie consent banner.
 *
 * HOW TO TEST:
 *   Paste into Oxbuild UI.
 *   C++ scanner redacts:
 *     user@example.com         → [PII_EMAIL_xxxxxxxx]
 *     AIzaSyD-9tSrke72...      → [PII_API_KEY_xxxxxxxx]  (Google API key)
 *     pk_live_51H7...          → [PII_API_KEY_xxxxxxxx]  (Stripe publishable)
 *   Expected violations: 6
 */

// ── EXPLOIT 1: API keys hardcoded in frontend bundle (ships to browser) ──────
// GDPR Art. 32 — Security of Processing
// Any user who visits the site can extract these from browser DevTools
const GOOGLE_ANALYTICS_KEY = 'AIzaSyD-9tSrke72Fh8pYvJxKLmN3oPqRsTuVwX';
const STRIPE_PUBLISHABLE   = 'pk_live_51H7AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
const SUPPORT_EMAIL        = 'user@example.com';
const MIXPANEL_TOKEN       = 'a1b2c3d4e5f6789012345678901234567890abcd';

// ── EXPLOIT 2: Full user object stored in localStorage ───────────────────────
// GDPR Art. 5(1)(c) — Data Minimisation
// GDPR Art. 32 — Insecure storage of personal data
// localStorage is accessible to any JavaScript on the page (XSS risk)
interface UserProfile {
  id:             number;
  email:          string;
  fullName:       string;
  dateOfBirth:    string;
  ssn:            string;    // SSN in frontend storage — never acceptable
  phoneNumber:    string;
  homeAddress:    string;
  creditScore:    number;
  medicalHistory: string[];
}

function storeUserProfile(user: UserProfile): void {
  // Stores complete profile including SSN and medical data in localStorage
  localStorage.setItem('user_profile', JSON.stringify(user));
  localStorage.setItem('user_ssn', user.ssn);          // explicit SSN storage
  localStorage.setItem('user_medical', JSON.stringify(user.medicalHistory));
  console.log('Stored user profile:', user);            // logs PII to browser console
}

// ── EXPLOIT 3: Analytics tracking without consent ────────────────────────────
// GDPR Art. 6 + Art. 7 — Lawfulness and Consent
// GDPR Art. 13 — Right to Information
// ePrivacy Directive — Cookie consent
function trackUserBehaviour(userId: number, action: string, metadata: object): void {
  // Fires analytics before consent banner is shown or accepted
  const profile = JSON.parse(localStorage.getItem('user_profile') || '{}') as UserProfile;

  fetch('https://analytics.thirdparty.io/track', {
    method: 'POST',
    body: JSON.stringify({
      user_id:   userId,
      email:     profile.email,       // PII sent to third-party analytics
      full_name: profile.fullName,    // without explicit consent
      action,
      metadata,
      timestamp: Date.now(),
    }),
  });
}

// ── EXPLOIT 4: Cookie consent banner that pre-checks all boxes ────────────────
// GDPR Art. 7(4) — Consent must be freely given
// GDPR Recital 32 — Pre-ticked boxes are not valid consent
function renderConsentBanner(): void {
  document.cookie = 'analytics_consent=true; max-age=31536000';    // set before user responds
  document.cookie = 'marketing_consent=true; max-age=31536000';

  const banner = document.createElement('div');
  banner.innerHTML = `
    <p>We use cookies to improve your experience.</p>
    <input type="checkbox" id="analytics" checked disabled />Analytics
    <input type="checkbox" id="marketing" checked disabled />Marketing
    <button onclick="closeBanner()">Accept All</button>
    <!-- No "Reject" option — GDPR requires ability to decline -->
    <!-- All boxes pre-checked and disabled — not valid consent -->
  `;
  document.body.appendChild(banner);
}

// ── EXPLOIT 5: Right to erasure — incomplete implementation ──────────────────
// GDPR Art. 17 — Right to Erasure
// CCPA §1798.105 — Right to Delete
async function deleteUserAccount(userId: number): Promise<void> {
  await fetch(`/api/users/${userId}`, { method: 'DELETE' });

  // Only clears the main profile — all other traces remain:
  localStorage.removeItem('user_profile');
  // Missing: sessionStorage.clear()
  // Missing: indexedDB cleanup
  // Missing: third-party data deletion requests (analytics, marketing)
  // Missing: server-side cascade (audit logs, backups, analytics warehouse)
  // Missing: confirmation email to user with deletion record

  console.log(`User ${userId} "deleted"`);   // not actually deleted from all systems
}

// ── EXPLOIT 6: Error boundary logs user PII to Sentry without scrubbing ───────
// GDPR Art. 32 — Appropriate security measures
window.addEventListener('error', (event) => {
  const userData = JSON.parse(localStorage.getItem('user_profile') || '{}');
  // Sends full user profile (including SSN, medical data) to Sentry on every error
  fetch('https://sentry.io/api/PROJECT_ID/store/', {
    method: 'POST',
    body: JSON.stringify({
      exception: event.error,
      user: userData,           // full PII including SSN and medical history
      extra: { localStorage: { ...localStorage } },  // entire localStorage dumped
    }),
  });
});

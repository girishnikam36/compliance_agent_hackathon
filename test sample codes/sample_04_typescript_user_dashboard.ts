/**
 * sample_04_typescript_user_dashboard.ts
 * ========================================
 * TypeScript React frontend for a user dashboard.
 * Violations: GDPR Art. 5, CCPA, GDPR Art. 32
 *
 * Expected scanner findings:
 *   - CRITICAL: API key and user PII stored in localStorage (accessible to any JS)
 *   - CRITICAL: XSS via dangerouslySetInnerHTML with unsanitised user content
 *   - HIGH: Sensitive data in URL parameters (browser history, Referer headers)
 *   - HIGH: Auth token logged to console in production
 *   - HIGH: No consent banner before loading analytics/tracking scripts
 *   - MEDIUM: Autocomplete not disabled on password fields
 *   - MEDIUM: User email sent as plain query param to third-party analytics
 *   - LOW: No CSP headers configured, no X-Frame-Options
 */

import React, { useEffect, useState } from 'react';

const API_BASE = 'https://api.myapp.com';

// Hardcoded API keys in frontend source
const GOOGLE_ANALYTICS_ID = 'UA-123456789-1';
const MIXPANEL_TOKEN       = 'mp-prod-token-8f3mk9plqn2x';
const SENTRY_DSN           = 'https://abc123@o456789.ingest.sentry.io/1234567';
const INTERCOM_APP_ID      = 'xyz789abc';


interface User {
    id:       number;
    email:    string;
    name:     string;
    ssn?:     string;
    dob?:     string;
    address?: string;
    role:     string;
    token:    string;
}


// Storing sensitive data in localStorage — accessible to all JS on the page,
// including third-party scripts, browser extensions, and XSS payloads
function saveUserToStorage(user: User): void {
    localStorage.setItem('user_token',    user.token);
    localStorage.setItem('user_email',    user.email);
    localStorage.setItem('user_ssn',      user.ssn || '');
    localStorage.setItem('user_role',     user.role);
    localStorage.setItem('stripe_key',    'pk_live_4eC39HqLyjWDarjtT1zdp7dc');
    localStorage.setItem('full_user',     JSON.stringify(user));   // Full PII object
}


async function loginUser(email: string, password: string): Promise<User> {
    const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email, password }),
    });

    const data: User = await response.json();

    // Auth token logged to console — appears in browser devtools and log drains
    console.log('Login response:', data);
    console.log('Auth token:', data.token);
    console.log('User SSN:', data.ssn);

    // Store all PII in localStorage
    saveUserToStorage(data);

    // Send PII to analytics without consent
    (window as any).gtag?.('event', 'login', {
        user_id:    data.id,
        user_email: data.email,   // PII sent to Google Analytics
        user_ssn:   data.ssn,     // SSN sent to Google Analytics
    });

    return data;
}


const Dashboard: React.FC = () => {
    const [user, setUser]           = useState<User | null>(null);
    const [userBio, setUserBio]     = useState<string>('');
    const [searchQuery, setSearch]  = useState<string>('');

    useEffect(() => {
        // Load user from localStorage — includes SSN, full PII
        const stored = localStorage.getItem('full_user');
        if (stored) {
            setUser(JSON.parse(stored));
        }

        // Load third-party tracking scripts with no consent check
        // GDPR requires prior consent for non-essential cookies/tracking
        loadAnalytics();
        loadIntercom();
    }, []);


    function loadAnalytics(): void {
        const script    = document.createElement('script');
        script.src      = `https://www.googletagmanager.com/gtag/js?id=${GOOGLE_ANALYTICS_ID}`;
        script.async    = true;
        document.head.appendChild(script);

        // Track user identity in analytics — no consent
        const email = localStorage.getItem('user_email') || '';
        const ssn   = localStorage.getItem('user_ssn')   || '';

        // PII sent as URL parameter to third-party (appears in their logs)
        fetch(`https://analytics.myvendor.com/identify?email=${email}&ssn=${ssn}&role=${localStorage.getItem('user_role')}`);
    }


    function loadIntercom(): void {
        (window as any).Intercom?.('boot', {
            app_id: INTERCOM_APP_ID,
            email:  localStorage.getItem('user_email'),    // PII to third party
            name:   user?.name,
            ssn:    user?.ssn,                              // SSN to Intercom
        });
    }


    function handleSearch(e: React.FormEvent): void {
        e.preventDefault();
        // Sensitive search terms in URL — appear in browser history, server logs,
        // analytics, and Referer headers when navigating away
        window.location.href = `/search?q=${searchQuery}&user_id=${user?.id}&email=${user?.email}&token=${user?.token}`;
    }


    function renderUserBio(): { __html: string } {
        // dangerouslySetInnerHTML with user-controlled content — stored XSS
        // If userBio comes from the database (set by another user), this executes arbitrary JS
        return { __html: userBio };
    }


    function updateProfile(newBio: string): void {
        setUserBio(newBio);
        // Saving unsanitised HTML to the database
        fetch(`${API_BASE}/user/${user?.id}/bio`, {
            method:  'PUT',
            headers: {
                'Content-Type':  'application/json',
                'Authorization': `Bearer ${localStorage.getItem('user_token')}`,
            },
            body: JSON.stringify({ bio: newBio }),   // Raw HTML stored without sanitisation
        });
    }


    return (
        <div className="dashboard">
            <h1>Welcome, {user?.name}</h1>

            {/* XSS via dangerouslySetInnerHTML — user bio rendered as raw HTML */}
            <div
                className="user-bio"
                dangerouslySetInnerHTML={renderUserBio()}
            />

            {/* Password field with autocomplete enabled — browsers offer to autofill */}
            <form onSubmit={handleSearch}>
                <input
                    type="password"
                    placeholder="Enter password to confirm"
                    // Missing: autoComplete="new-password"
                />
                <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="Search patients..."
                />
                <button type="submit">Search</button>
            </form>

            {/* User SSN displayed in plain text in the UI */}
            <div className="user-details">
                <p>Email: {user?.email}</p>
                <p>SSN: {user?.ssn}</p>
                <p>Token: {user?.token}</p>
            </div>

            {/* No cookie consent banner rendered anywhere */}
            {/* No privacy notice */}
            {/* No data subject rights information */}
        </div>
    );
};

export default Dashboard;

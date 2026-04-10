# Oxbuild Compliance Agent

**License: MIT + Commons Clause v1.0** — Community use is free. Commercial use (SaaS, products, hosted services) requires written permission from the author. Hackathon evaluation does not grant commercial rights. See [LICENSE](./LICENSE) and [NOTICE.md](./NOTICE.md).

---

Oxbuild scans source code for data privacy and security violations before they ship. Paste your code, upload a file, or take a screenshot of code from anywhere — and within 20 seconds you get a list of violations, a risk score, a patched version of your code, and a PDF report.

It works on Python, JavaScript, TypeScript, Java, Go, and more.

Before any code reaches an AI model, a local scanner strips all real data — emails, API keys, IP addresses — and replaces them with tokens like `[PII_EMAIL_3F2A]`. Your actual data never leaves your machine.

---

## What it catches

The scanner checks your code against GDPR, DPDPA, CCPA, HIPAA, and PCI-DSS. Here are the kinds of things it finds:

- Hardcoded credentials and API keys in source code
- Patient health data (PHI) written to logs in plaintext
- Raw payment card numbers stored or transmitted
- SQL injection via string concatenation
- `SELECT *` on tables containing personal data (no data minimisation)
- Webhook handlers that skip signature verification
- MD5 used for pseudonymisation (cryptographically broken)
- No consent check before processing personal data
- XSS via unsanitised HTML injection
- Missing rate limiting on authentication endpoints
- Sensitive data returned in HTTP error responses

Each finding comes with the exact regulation and article number, the specific line of code, and a concrete fix.

---

## How the pipeline works

```
Your code (raw)
      |
      v
Phase 0 — Local PII scanner
  C++ regex engine (Python fallback if not compiled)
  Strips: emails, API keys, IPs, phone numbers
  Output: code with [PII_EMAIL_3F2A] placeholder tokens
      |
      v
Phase 1 — Legal Auditor  (Oxlo.ai: gpt-oss-120b)
  Reads the sanitized code
  Maps every violation to its exact regulation and article
  Returns a structured list of findings
      |
      v
Phase 2 — Risk Judge  (Oxlo.ai: deepseek-r1-0528)
  Applies the formula: Score = min(100, sum(Severity x Likelihood) / (10 x N) x 100)
  Predicts fine ranges in EUR per regulation
  The model shows its reasoning before committing to a number
      |
      v
Phase 3 — Architect  (Oxlo.ai: deepseek-coder-33b)
  Generates a surgical patch for each violation
  Patches are applied programmatically — no guessing
  Output: corrected file + line-by-line diff
      |
      v
PDF report
  Cover page, violation cards, risk breakdown, corrected code, split diff
```

The multimodal path adds one step before Phase 0: if you upload an image, a vision model (Oxlo.ai: llama-3.2-11b-vision-instruct) reads the screenshot and extracts the source code first.

---

## AI models used

All four models are accessed through Oxlo.ai at `https://api.oxlo.ai/v1`.

| Phase | Model | Why |
|-------|-------|-----|
| Auditor | gpt-oss-120b | Largest model on Oxlo. Needed for zero-hallucination output on regulation articles and JSON field names. |
| Judge | deepseek-r1-0528 | Reasoning model. Shows its working in `<think>` blocks before scoring — makes risk numbers auditable. |
| Architect | deepseek-coder-33b | Code-specialised. Produces syntactically valid patches with correct indentation and language-appropriate comments. |
| Vision | llama-3.2-11b-vision-instruct | Extracts source code from screenshots and photos for the multimodal scan path. |

---

## Quick start

You need Python 3.11+, Node.js 18+, and an Oxlo.ai API key from https://portal.oxlo.ai.

```bash
git clone https://github.com/girishnikam36/compliance_agent_hackathon.git
cd oxbuild-compliance-agent

# Configure
cp .env.example .env
# Open .env and set: OXLO_API_KEY=your_key_here and ENABLE_MOCK_LLM=false

# Install Python dependencies
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start the backend
cd cloud_orchestrator
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# In a new terminal, start the frontend
cd local_bridge/ui
npm install
npm run dev
```

Open http://localhost:5173.

---

## How to test the scanner

The `test_samples/` folder in this repo has 10 code files built specifically to test different aspects of the scanner. Here is how to use them.

### Running a test

1. Open the app at http://localhost:5173 (or the live demo URL above)
2. Click the **Upload** tab on the left panel
3. Drag and drop one of the sample files, or click to browse and select it
4. The language is detected automatically from the file extension
5. Select the regulations you want to check against using the toggle buttons (GDPR, HIPAA, etc.)
6. Click **Sanitize and Audit**
7. Wait 15-30 seconds — results appear in the three tabs on the right

You can also paste code directly: click the **Paste** tab, copy the contents of any sample file, paste it in, and click Audit.

To test the multimodal path: take a screenshot of any sample file open in your editor, then upload the image using the image upload button.

### What each sample file tests

**sample_01_django_healthcare_api.py**
A Django REST API for a hospital patient management system. This one has the most severe violations — hardcoded database credentials, patient health data (SSNs, diagnoses) logged in plaintext, a permanent emergency override that bypasses all access controls, and MD5 used for patient pseudonymisation. Use this to see what a CRITICAL/HIGH risk score looks like with full HIPAA and GDPR Art. 9 findings.

**sample_02_nodejs_payment_gateway.js**
A Node.js payment service that accepts raw card numbers directly from clients, stores them in a database, and processes Stripe webhooks without verifying the signature. This tests PCI-DSS detection — your scanner should flag the raw PAN storage and the missing `stripe.webhooks.constructEvent()` call.

**sample_03_python_user_auth_service.py**
A Flask authentication service using MD5 for passwords (no salt), `random.randint` for reset tokens instead of `secrets.token_urlsafe`, and a JWT signed with a hardcoded key. Also has user enumeration (different error messages for "user not found" vs "wrong password") and no rate limiting on login.

**sample_04_typescript_user_dashboard.ts**
A TypeScript React frontend that stores user SSNs and auth tokens in `localStorage`, uses `dangerouslySetInnerHTML` with unescaped user content (stored XSS), and loads Google Analytics and Intercom without a consent banner. Tests client-side violation detection.

**sample_05_python_data_pipeline.py**
An ETL pipeline that copies full customer records (including SSNs and health data) from a production database to a Snowflake analytics warehouse with no anonymisation, no purpose limitation check, and no data processing agreement with the third-party vendor. Tests GDPR Art. 5 and Art. 6 detection.

**sample_06_nodejs_graphql_api.js**
A GraphQL API with introspection enabled in production, no query depth or complexity limits (denial of service via deeply nested queries), and raw card numbers directly in the schema. Also has broken object-level authorisation — any user can query any other user's private messages and payment methods.

**sample_07_python_ml_training_pipeline.py**
A machine learning pipeline that uses real production customer data (including SSNs, health conditions, and ethnicity) as training features for a credit scoring model, with no Art. 22 disclosure about automated decision-making and no right-to-explanation mechanism.

**sample_08_nodejs_file_upload_service.js**
A file upload service with path traversal in the download endpoint (`../../etc/passwd` works), command injection via filenames passed to `exec()`, server-side request forgery in a document preview endpoint, and XML external entity injection in the metadata parser.

**sample_09_python_compliant_baseline.py**
This one has zero violations. It is a correctly implemented user management API using bcrypt, `secrets.token_urlsafe`, parameterised queries, structured logging with no PII, soft-delete with audit trail, and explicit field allowlists. Use this to check that your scanner does not produce false positives on clean code.

**sample_10_nodejs_iot_telemetry_service.js**
An IoT telemetry service for a wearables platform that stores raw health metrics (heart rate, blood glucose, GPS coordinates) unencrypted, shares them with insurance partners without consent checks, and broadcasts all health data over an unauthenticated WebSocket connection.

### What a good test run looks like

| Sample | Expected risk level | Critical count | Should trigger |
|--------|--------------------|--------------:|----------------|
| 01 | CRITICAL (80-100) | 3-4 | HIPAA, GDPR Art. 9, PCI-DSS |
| 02 | CRITICAL (75-95) | 2-3 | PCI-DSS, GDPR Art. 5 |
| 03 | HIGH (60-80) | 1-2 | GDPR Art. 32 |
| 04 | HIGH (55-75) | 1 | GDPR Art. 32, CCPA |
| 05 | HIGH (55-70) | 0-1 | GDPR Art. 5, 6, 25 |
| 06 | HIGH (60-75) | 1-2 | GDPR Art. 25, PCI-DSS |
| 07 | HIGH (55-70) | 0-1 | GDPR Art. 22, 25 |
| 08 | CRITICAL (80-100) | 3-4 | GDPR Art. 32 |
| 09 | MINIMAL (0-10) | 0 | Nothing — clean code |
| 10 | CRITICAL (75-95) | 2-3 | HIPAA, GDPR Art. 9 |

If sample_09 comes back with violations, that is a false positive to investigate. If samples 01, 02, and 08 come back with a LOW score, the severity calibration needs looking at.

---

## API endpoints

The backend exposes these endpoints. You can explore them interactively at `/api/docs` once the server is running.

| Method | Endpoint | What it does |
|--------|----------|--------------|
| POST | /api/v1/scan | Strips PII from code locally. Returns sanitized code and a redaction map. |
| POST | /api/v1/scan/image | Accepts an image, extracts code, runs full audit. |
| POST | /api/v1/audit | Full pipeline — violations, risk score, patched code. |
| POST | /api/v1/audit/project | Accepts multiple files or a .zip archive. |
| POST | /api/v1/export/pdf | Accepts the audit result JSON, returns a PDF download. |
| GET | /api/v1/health | Server status and uptime. |
| GET | /api/v1/models | Which Oxlo.ai models are currently configured. |

---

## Deployment

The live demo runs on Railway (backend) and Vercel (frontend). See [DEPLOY.md](./DEPLOY.md) for the full setup guide — it covers everything from creating accounts to setting environment variables to verifying the deployment works end to end.

The short version:

1. Push this repo to GitHub
2. Deploy the backend to Railway (connect repo, add env vars, generate domain)
3. Deploy the frontend to Vercel (connect repo, set root dir to `local_bridge/ui`, add `VITE_API_BASE`)
4. Add your Vercel URL to `ALLOWED_ORIGINS` in Railway

Both services auto-rebuild on every `git push`.

---

## CI/CD

The `.github/workflows/oxbuild-scan.yml` file adds a compliance gate to pull requests. It scans changed files on every PR and fails the build if any CRITICAL violations are found. It also posts a summary comment directly on the PR with the violation details.

To enable it, add a secret called `GROQ_API_KEY` to your GitHub repo (Settings -> Secrets -> Actions).

---

## Supported regulations

| Regulation | What is checked |
|------------|-----------------|
| GDPR | Articles 5, 6, 9, 17, 22, 25, 32, 83 |
| DPDPA | Sections 6, 8, 10 |
| HIPAA | 164.308, 164.312, 164.502 |
| PCI-DSS | Requirements 3, 6, 7 |
| CCPA | 1798.100, 1798.105, 1798.155 |
| SOC 2 | CC6, CC7 |

---

## Contributing

If you find a false positive, a missed violation type, or have an improvement — open an issue or a pull request. The codebase is straightforward to navigate: `cloud_orchestrator/agents/pipeline.py` is where the three LLM phases live, and `cloud_orchestrator/utils/pdf_reporter.py` handles the PDF generation.

Please keep contributions under the same MIT + Commons Clause license.

---

## License

MIT + Commons Clause v1.0.

Copyright (c) 2025 Girish Nikam

Community use is free — personal projects, research, learning, internal tools, contributions. Commercial use (selling it, hosting it as a service, building a product from it) requires a separate written agreement with the author.

Contact for commercial licensing: nikamgirish38@gmail.com

Full terms: [LICENSE](./LICENSE) and [NOTICE.md](./NOTICE.md)

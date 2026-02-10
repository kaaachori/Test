const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;

const SECURITY_HEADERS = [
  {
    key: 'strict-transport-security',
    title: 'Strict-Transport-Security (HSTS)',
    severity: 'High',
    purpose: 'Forces browsers to use HTTPS and blocks protocol downgrade attacks.',
    bestPractice: 'Use at least max-age=31536000; includeSubDomains; preload where possible.',
    validate: (value) => {
      const normalized = String(value || '').toLowerCase();
      return normalized.includes('max-age=')
        ? { status: 'present', details: 'HSTS is configured.' }
        : { status: 'misconfigured', details: 'HSTS header exists but max-age is missing.' };
    }
  },
  {
    key: 'content-security-policy',
    title: 'Content-Security-Policy (CSP)',
    severity: 'Critical',
    purpose: 'Mitigates XSS and data injection by whitelisting trusted content sources.',
    bestPractice: "Define strict directives (default-src 'self'; object-src 'none'; frame-ancestors etc.).",
    validate: (value) => {
      const normalized = String(value || '').toLowerCase();
      if (!normalized.includes('default-src')) {
        return { status: 'misconfigured', details: 'CSP is missing default-src directive.' };
      }
      return { status: 'present', details: 'CSP exists and includes default-src.' };
    }
  },
  {
    key: 'x-frame-options',
    title: 'X-Frame-Options',
    severity: 'Medium',
    purpose: 'Prevents clickjacking by restricting framing.',
    bestPractice: 'Use DENY or SAMEORIGIN (or use CSP frame-ancestors).',
    validate: (value) => {
      const normalized = String(value || '').toUpperCase();
      if (['DENY', 'SAMEORIGIN'].some((v) => normalized.includes(v))) {
        return { status: 'present', details: 'Header is configured with a safe policy.' };
      }
      return { status: 'misconfigured', details: 'Header value should be DENY or SAMEORIGIN.' };
    }
  },
  {
    key: 'x-content-type-options',
    title: 'X-Content-Type-Options',
    severity: 'Medium',
    purpose: 'Blocks MIME-type sniffing attacks.',
    bestPractice: 'Set to nosniff.',
    validate: (value) => {
      return String(value || '').toLowerCase().trim() === 'nosniff'
        ? { status: 'present', details: 'nosniff is correctly configured.' }
        : { status: 'misconfigured', details: 'Header should be set to nosniff.' };
    }
  },
  {
    key: 'referrer-policy',
    title: 'Referrer-Policy',
    severity: 'Low',
    purpose: 'Controls referrer information leakage.',
    bestPractice: 'Use strict-origin-when-cross-origin (or stricter if needed).',
    validate: (value) => {
      const allowed = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
      return allowed.includes(String(value || '').toLowerCase().trim())
        ? { status: 'present', details: 'Referrer policy is explicitly configured.' }
        : { status: 'misconfigured', details: 'Policy is weak or missing.' };
    }
  },
  {
    key: 'permissions-policy',
    title: 'Permissions-Policy',
    severity: 'Low',
    purpose: 'Restricts browser feature access (camera, mic, geolocation, etc.).',
    bestPractice: 'Deny unused features and allow only trusted origins.',
    validate: (value) => {
      return String(value || '').trim().length > 0
        ? { status: 'present', details: 'Permissions policy detected.' }
        : { status: 'misconfigured', details: 'Empty policy value detected.' };
    }
  },
  {
    key: 'cross-origin-opener-policy',
    title: 'Cross-Origin-Opener-Policy',
    severity: 'Low',
    purpose: 'Isolates browsing context to reduce cross-origin risks.',
    bestPractice: 'Use same-origin for stronger isolation when compatible.',
    validate: (value) => {
      const v = String(value || '').toLowerCase();
      return v.includes('same-origin')
        ? { status: 'present', details: 'COOP configured for isolation.' }
        : { status: 'misconfigured', details: 'Recommended value is same-origin.' };
    }
  },
  {
    key: 'cross-origin-resource-policy',
    title: 'Cross-Origin-Resource-Policy',
    severity: 'Low',
    purpose: 'Restricts which sites can load resources from this origin.',
    bestPractice: 'Set to same-site or same-origin based on architecture.',
    validate: (value) => {
      const v = String(value || '').toLowerCase();
      return ['same-origin', 'same-site', 'cross-origin'].includes(v)
        ? { status: 'present', details: 'CORP policy explicitly declared.' }
        : { status: 'misconfigured', details: 'Invalid or missing CORP value.' };
    }
  }
];

function sanitizeUrl(input) {
  const url = new URL(input);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only http and https protocols are supported.');
  }
  return url.toString();
}

function fetchHeaders(targetUrl) {
  return new Promise((resolve, reject) => {
    const client = targetUrl.startsWith('https') ? require('https') : require('http');
    const request = client.request(targetUrl, {
      method: 'GET',
      timeout: 12000,
      headers: { 'User-Agent': 'SecurityHeaderInspector/1.0' }
    }, (response) => {
      response.resume();
      resolve({
        statusCode: response.statusCode,
        statusMessage: response.statusMessage,
        headers: response.headers
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error('Request timed out while trying to reach target URL.'));
    });

    request.on('error', reject);
    request.end();
  });
}

function buildReport(headers, targetUrl, statusCode) {
  const findings = SECURITY_HEADERS.map((item) => {
    const value = headers[item.key];
    if (!value) {
      return {
        ...item,
        status: 'missing',
        value: 'Not detected',
        details: `Missing ${item.title}.`
      };
    }

    const check = item.validate(value);
    return {
      ...item,
      status: check.status,
      value,
      details: check.details
    };
  });

  const score = findings.reduce((acc, finding) => {
    if (finding.status === 'present') {
      return acc + 12.5;
    }
    if (finding.status === 'misconfigured') {
      return acc + 6.25;
    }
    return acc;
  }, 0);

  const highRisk = findings.filter((f) => f.status !== 'present' && ['Critical', 'High'].includes(f.severity));
  const mediumRisk = findings.filter((f) => f.status !== 'present' && f.severity === 'Medium');

  return {
    metadata: {
      targetUrl,
      scannedAt: new Date().toISOString(),
      statusCode,
      score: Math.round(score)
    },
    executiveSummary:
      `The assessment reviewed ${SECURITY_HEADERS.length} key browser security headers for ${targetUrl}. ` +
      `Overall security header maturity score: ${Math.round(score)}/100. ` +
      `${highRisk.length} high/critical and ${mediumRisk.length} medium findings require remediation.`,
    findings,
    recommendations: findings
      .filter((f) => f.status !== 'present')
      .map((f) => ({
        header: f.title,
        severity: f.severity,
        action: f.bestPractice,
        rationale: f.purpose
      })),
    limitations: [
      'This report evaluates HTTP response headers only; it does not perform authenticated testing, business logic testing, or active exploitation.',
      'A complete VAPT should include network, application, authentication, authorization, and runtime behavior assessments.'
    ]
  };
}

function writeJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

const server = http.createServer(async (req, res) => {
  if (req.url === '/' && req.method === 'GET') {
    const filePath = path.join(__dirname, 'index.html');
    fs.createReadStream(filePath).pipe(res);
    return;
  }

  if (req.url === '/api/check' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.socket.destroy();
      }
    });

    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body || '{}');
        const targetUrl = sanitizeUrl(parsed.url || '');
        const responseData = await fetchHeaders(targetUrl);
        const report = buildReport(responseData.headers, targetUrl, responseData.statusCode);
        writeJson(res, 200, report);
      } catch (error) {
        writeJson(res, 400, { error: error.message || 'Unable to process URL.' });
      }
    });

    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// On-demand, read-only scan of the explicitly allowed public scanner testbed.
const TARGET = 'https://public-firing-range.appspot.com/';
const PATHS = ['/', '/mixedcontent/index.html', '/clickjacking/index.html'];
const MAX_BODY = 256 * 1024;
const MAX_REQUEST = 4096;
const TIMEOUT_MS = 5000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function sameSecret(received, expected) {
  if (typeof expected !== 'string' || expected.length < 32 || typeof received !== 'string') return false;
  const a = new TextEncoder().encode(received);
  const b = new TextEncoder().encode(expected);
  if (a.length > 256 || b.length > 256) return false;
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) difference |= (a[i] || 0) ^ (b[i] || 0);
  return difference === 0;
}

async function readBounded(stream, limit) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new Error('body_too_large');
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function analyzeText(url, text, contentType) {
  const findings = [];
  if (!/text\/html|text\/plain/i.test(contentType)) return findings;
  if (/\bapi[_-]?key\s*[:=]\s*[A-Za-z0-9._-]{6,}/i.test(text)) {
    findings.push({ category: 'sensitive_exposure', url, evidence_masked: 'api_key=[REDACTED]',
      verification: 'pending', severity: 'pending' });
  }
  if (/text\/html/i.test(contentType) && /<script\b[^>]*\bsrc\s*=\s*["']http:\/\//i.test(text)) {
    findings.push({ category: 'mixed_content', url,
      evidence_masked: 'HTTPS page loads a script over HTTP', verification: 'pending', severity: 'pending' });
  }
  return findings;
}

function inspectHtmlResources(url, text) {
  const observations = [];
  for (const match of text.matchAll(/<(script|link|img|iframe|source)\b[^>]*>/gi)) {
    const tag = match[1].toLowerCase();
    if (tag === 'script' || (tag === 'link' && !/\brel\s*=\s*["']?stylesheet\b/i.test(match[0]))) continue;
    if (!/\b(?:src|href|srcset)\s*=\s*["']?http:\/\//i.test(match[0])) continue;
    observations.push({ category: 'http_resource_reference', url,
      evidence_masked: `HTTPS page references an HTTP ${tag} resource`,
      verification: 'pending', severity: 'pending' });
  }
  return observations;
}

async function scan(fetcher = fetch) {
  const pages = [];
  const findings = [];
  const observations = [];
  const resourceObservations = [];
  const errors = [];
  for (const path of PATHS) {
    const url = new URL(path, TARGET).href;
    try {
      const response = await fetcher(url, {
        method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { accept: 'text/html,text/plain;q=0.9' },
      });
      pages.push({ url, status: response.status });
      if (response.status !== 200) continue;
      if (!response.headers.has('x-content-type-options')) {
        observations.push({ category: 'missing_security_header', url,
          evidence_masked: 'X-Content-Type-Options header absent',
          verification: 'pending', severity: 'pending' });
      }
      const contentType = response.headers.get('content-type') || '';
      if (!/text\/html|text\/plain/i.test(contentType)) continue;
      if (/text\/html/i.test(contentType) &&
          !response.headers.has('x-frame-options') &&
          !/\bframe-ancestors\b/i.test(response.headers.get('content-security-policy') || '')) {
        observations.push({ category: 'missing_frame_protection', url,
          evidence_masked: 'Neither X-Frame-Options nor CSP frame-ancestors observed',
          verification: 'pending', severity: 'pending' });
      }
      const body = await readBounded(response.body, MAX_BODY);
      const text = new TextDecoder().decode(body);
      findings.push(...analyzeText(url, text, contentType));
      if (/text\/html/i.test(contentType)) resourceObservations.push(...inspectHtmlResources(url, text));
    } catch (error) {
      errors.push({ url, error: error.message === 'body_too_large' ? 'body_too_large' : 'request_failed' });
    }
  }
  return {
    scan_id: new Date().toISOString(), simulated: false, data_kind: 'public_scanner_testbed',
    execution_mode: 'on_demand', target_url: TARGET,
    scan_status: errors.length || pages.some(page => page.status !== 200) ? 'partial' : 'complete',
    pages, findings, resolved_findings: [], changes: [], baseline_available: false, errors,
    tool_checks: [
      { tool: 'http_header_audit', status: errors.length ? 'partial' : 'ok', method: 'GET', observations },
      { tool: 'html_resource_audit', status: errors.length ? 'partial' : 'ok', method: 'GET', observations: resourceObservations },
    ],
  };
}

async function handle(request, env, fetcher = fetch) {
  const path = new URL(request.url).pathname;
  if (request.method === 'GET' && path === '/health') return json({ status: 'ok' });
  if (request.method !== 'POST' || path !== '/scan') return json({ error: 'Not found' }, 404);
  if (!env.SCAN_API_KEY || env.SCAN_API_KEY.length < 32) return json({ error: 'Service not configured' }, 503);
  if (!sameSecret(request.headers.get('x-api-key'), env.SCAN_API_KEY)) return json({ error: 'Unauthorized' }, 401);
  try {
    const body = await readBounded(request.body, MAX_REQUEST);
    const input = JSON.parse(new TextDecoder().decode(body));
    if (!input || input.target_url !== TARGET || Object.keys(input).some(key => key !== 'target_url')) {
      return json({ error: 'Target is not in the configured scan scope' }, 400);
    }
  } catch {
    return json({ error: 'Invalid JSON or request body too large' }, 400);
  }
  const result = await scan(fetcher);
  return json({ result_key: JSON.stringify(result), ...result });
}

export { TARGET, PATHS, analyzeText, scan, handle };

// On-demand, read-only inspection of a user-supplied public HTTP(S) website.
const TARGET = 'https://public-firing-range.appspot.com/';
const PATHS = ['/', '/mixedcontent/index.html', '/clickjacking/index.html'];
const MAX_PAGES = 3;
const MAX_BODY = 256 * 1024;
const MAX_REQUEST = 4096;
const TIMEOUT_MS = 5000;
const BLACKLIST_SUFFIXES = ['gov.cn', 'mil.cn', 'xn--zfr164b.cn', 'gov', 'mil'];
const BLACKLIST_EXACT = ['zwfw.cscse.edu.cn', 'hengnao-authorized-scan.pages.dev'];
const NONPUBLIC_SUFFIXES = ['localhost', 'local', 'internal', 'test', 'invalid', 'onion'];

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

function hasSuffix(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

function validateTarget(raw) {
  if (typeof raw !== 'string' || raw.length > 2048 || /\s/.test(raw)) return { reason: 'invalid_target' };
  let url;
  try { url = new URL(raw); } catch { return { reason: 'invalid_target' }; }
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.port || url.hash || !host.includes('.') || !/^[a-z0-9.-]+$/.test(host) ||
      host.includes('..') || host.startsWith('-') || host.endsWith('-') ||
      host.includes(':') || /^\d+(?:\.\d+)*$/.test(host)) return { reason: 'invalid_target' };
  if (BLACKLIST_EXACT.includes(host) || BLACKLIST_SUFFIXES.some(suffix => hasSuffix(host, suffix)) ||
      NONPUBLIC_SUFFIXES.some(suffix => hasSuffix(host, suffix))) return { reason: 'blocked_target' };
  return { url };
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
  if (url.startsWith('https:') && /text\/html/i.test(contentType) &&
      /<script\b[^>]*\bsrc\s*=\s*["']http:\/\//i.test(text)) {
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

function discoverLinks(text, base, origin) {
  const links = [];
  for (const match of text.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    try {
      const link = new URL(match[1] ?? match[2] ?? match[3], base);
      link.hash = '';
      if (link.origin === origin && !/(?:logout|signout|delete|remove|reset)/i.test(link.pathname)) {
        links.push(link.href);
      }
    } catch { /* Ignore malformed links. */ }
    if (links.length >= 20) break;
  }
  return links;
}

async function scan(fetcher = fetch, target = TARGET) {
  const targetUrl = new URL(target);
  const queue = target === TARGET ? PATHS.map(path => new URL(path, TARGET).href) : [targetUrl.href];
  const seen = new Set();
  const pages = [];
  const findings = [];
  const observations = [];
  const resourceObservations = [];
  const errors = [];
  while (queue.length && seen.size < MAX_PAGES) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);
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
      if (/text\/html/i.test(contentType)) {
        if (url.startsWith('https:')) resourceObservations.push(...inspectHtmlResources(url, text));
        if (target !== TARGET) {
          for (const link of discoverLinks(text, url, targetUrl.origin)) {
            if (!seen.has(link) && !queue.includes(link) && queue.length + seen.size < MAX_PAGES) queue.push(link);
          }
        }
      }
    } catch (error) {
      errors.push({ url, error: error.message === 'body_too_large' ? 'body_too_large' : 'request_failed' });
    }
  }
  const partial = errors.length || pages.some(page => page.status !== 200);
  return {
    scan_id: new Date().toISOString(), simulated: false,
    data_kind: target === TARGET ? 'public_scanner_testbed' : 'user_supplied_public_url',
    execution_mode: 'on_demand', target_url: target, scan_status: partial ? 'partial' : 'complete',
    scan_scope: { max_pages: MAX_PAGES, same_origin: true, methods: ['GET'], redirects: 'manual' },
    pages, findings, resolved_findings: [], changes: [], baseline_available: false, errors,
    tool_checks: [
      { tool: 'http_header_audit', status: partial ? 'partial' : 'ok', method: 'GET', observations },
      { tool: 'html_resource_audit', status: partial ? 'partial' : 'ok', method: 'GET', observations: resourceObservations },
    ],
  };
}

async function handle(request, env, fetcher = fetch) {
  const path = new URL(request.url).pathname;
  if (request.method === 'GET' && path === '/health') return json({ status: 'ok' });
  if (request.method !== 'POST' || path !== '/scan') return json({ error: 'Not found' }, 404);
  if (!env.SCAN_API_KEY || env.SCAN_API_KEY.length < 32) return json({ error: 'Service not configured' }, 503);
  if (!sameSecret(request.headers.get('x-api-key'), env.SCAN_API_KEY)) return json({ error: 'Unauthorized' }, 401);
  let input;
  try {
    const body = await readBounded(request.body, MAX_REQUEST);
    input = JSON.parse(new TextDecoder().decode(body));
    if (!input || typeof input.target_url !== 'string' ||
        Object.keys(input).some(key => key !== 'target_url')) throw new Error('invalid');
  } catch { return json({ error: 'Invalid JSON or request body too large' }, 400); }
  const validation = validateTarget(input.target_url);
  if (!validation.url) {
    // The connected HengNao tool still runs when its route node declines a target.
    const rejected = { scan_status: 'rejected', reason: validation.reason,
      execution_mode: 'on_demand', target_url: '', pages: [], findings: [],
      resolved_findings: [], changes: [], errors: [], tool_checks: [] };
    return json({ result_key: JSON.stringify(rejected), ...rejected });
  }
  const result = await scan(fetcher, input.target_url);
  return json({ result_key: JSON.stringify(result), ...result });
}

export { TARGET, PATHS, validateTarget, analyzeText, scan, handle };

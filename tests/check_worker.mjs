import assert from 'node:assert/strict';
import test from 'node:test';
import { handle, PATHS, TARGET } from '../cloudflare/scan-core.mjs';

const key = 'test-key-with-more-than-thirty-two-characters';
const request = (target = TARGET, sentKey = key) => new Request('https://worker.example/scan', {
  method: 'POST', headers: { 'x-api-key': sentKey, 'content-type': 'application/json' },
  body: JSON.stringify({ target_url: target }),
});

test('rejects an unlisted target before any outbound request', async () => {
  let called = false;
  const response = await handle(request('https://example.com/'), { SCAN_API_KEY: key }, () => { called = true; });
  assert.equal(response.status, 400);
  assert.equal(called, false);
});

test('requires the configured API key', async () => {
  const response = await handle(request(TARGET, 'wrong'), { SCAN_API_KEY: key }, () => { throw Error('called'); });
  assert.equal(response.status, 401);
});

test('requests only three allowlisted pages and returns masked evidence', async () => {
  const urls = [];
  const fetcher = async (url, options) => {
    urls.push(url);
    assert.equal(options.redirect, 'manual');
    return new Response(url.endsWith('mixedcontent/index.html')
      ? '<script src="http://example.invalid/example.js"></script>' : '<h1>test</h1>', {
      status: 200, headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  };
  const response = await handle(request(), { SCAN_API_KEY: key }, fetcher);
  const data = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(urls, PATHS.map(path => new URL(path, TARGET).href));
  assert.equal(data.execution_mode, 'on_demand');
  assert.deepEqual(JSON.parse(data.result_key).pages, data.pages);
  assert.equal(data.scan_status, 'complete');
  assert.equal(data.findings.length, 1);
  assert.equal(data.findings[0].category, 'mixed_content');
  assert.equal(data.tool_checks[0].observations.length, 3);
});

test('reports a failed page as incomplete', async () => {
  const data = await (await handle(request(), { SCAN_API_KEY: key }, async url => {
    if (url.endsWith('mixedcontent/index.html')) throw Error('network');
    return new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } });
  })).json();
  assert.equal(data.scan_status, 'partial');
  assert.equal(data.errors.length, 1);
  assert.equal(data.pages.length, 2);
});

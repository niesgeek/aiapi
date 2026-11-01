// ==========================================
// API Proxy Service (Cloudflare Workers Native)
// ssrf 分支：基于 main 分支的加固版
// 加固点：
//  1. 网关鉴权：必须在 Worker 环境变量里设置 PROXY_KEY，
//     调用方须在请求头里带 x-proxy-key: <PROXY_KEY>，否则 401。
//     注意：这与上游 API Key 是两回事，上游 Key 仍用 Authorization / x-api-key 照常转发。
//  2. /proxy 默认关闭：只有 PROXY_ALLOWED_HOSTS（逗号分隔的精确域名）
//     非空时才开放，且只允许 https、只允许白名单内的精确域名。
//  3. 前缀匹配改为最长优先 + 边界检查，避免 /openai-evil 被当成 /openai。
//  4. 屏蔽内网/回环/链路本地/元数据主机名与 IP 字面量，/proxy 改为手动跟随
//     重定向并逐跳校验 Location，禁止借重定向跳到白名单外。
//  5. 只放行白名单请求头、只透传安全的响应头（删 set-cookie 等逐跳头），
//     不把上游内部错误信息原样返回，统一返回通用错误。
//  6. 请求体上限 10 MB、上游超时 30 秒。
//  局限（请务必读 DEPLOY.md）：Workers 在 fetch 之前无法可靠地把域名解析
//  成 IP 再做内网段拦截，DNS 重绑定类攻击不能仅靠本文件 100% 挡住，
//  因此白名单是本分支的核心防线；不要把 /proxy 的白名单放得过大，
//  生产上还应在 Cloudflare 侧加 Rate Limiting / WAF。
// ==========================================

const apiMapping = {
  '/openai': 'https://api.openai.com',
  '/claude': 'https://api.anthropic.com',
  '/gemini': 'https://generativelanguage.googleapis.com',
  '/xai': 'https://api.x.ai',
  '/cohere': 'https://api.cohere.com',
  '/vertex': 'https://us-central1-aiplatform.googleapis.com/v1/publishers',
  '/deepseek': 'https://api.deepseek.com',
  '/moonshot': 'https://api.moonshot.cn',
  '/zhipu': 'https://open.bigmodel.cn/api/paas/v4',
  '/openrouter': 'https://openrouter.ai/api',
  '/groq': 'https://api.groq.com/openai',
  '/siliconflow': 'https://api.siliconflow.cn',
  '/together': 'https://api.together.xyz',
  '/fireworks': 'https://api.fireworks.ai',
  '/novita': 'https://api.novita.ai',
  '/portkey': 'https://api.portkey.ai',
  '/github': 'https://models.inference.ai.azure.com',
  '/replicate': 'https://api.replicate.com',
  '/akash': 'https://chatapi.akash.network/api',
  '/cerebras': 'https://api.cerebras.ai',
  '/nvidia': 'https://integrate.api.nvidia.com',
  '/hf': 'https://api-inference.huggingface.co',
  '/mistral': 'https://api.mistral.ai',
  '/perplexity': 'https://api.perplexity.ai',
  '/stability': 'https://api.stability.ai',
  '/elevenlabs': 'https://api.elevenlabs.io',
  '/voyage': 'https://api.voyageai.com',
  '/midjourney': 'https://api.midjourney.com',
  '/discord': 'https://discord.com/api',
  '/telegram': 'https://api.telegram.org',
// --- 新增：国产大模型（OpenAI 兼容） ---
  '/qwen': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
  '/doubao': 'https://ark.cn-beijing.volces.com/api/v3',
  '/hunyuan': 'https://api.hunyuan.cloud.tencent.com/v1',
  '/minimax': 'https://api.minimax.chat/v1',
  '/stepfun': 'https://api.stepfun.com/v1',
  '/baichuan': 'https://api.baichuan-ai.com/v1',
  '/spark': 'https://spark-api-open.xf-yun.com/v1',
  '/qianfan': 'https://qianfan.baidubce.com/v2',

  // --- 新增：聚合 & 开源推理（OpenAI 兼容） ---
  '/deepinfra': 'https://api.deepinfra.com/v1/openai',
  '/nebius': 'https://api.studio.nebius.com/v1',
  '/sambanova': 'https://api.sambanova.ai/v1',
  '/hyperbolic': 'https://api.hyperbolic.xyz/v1',
  '/chutes': 'https://llm.chutes.ai/v1',
  '/llama': 'https://api.llama.com/compat/v1',

  // --- 新增：多模态（图像/视频/语音） ---
  '/fal': 'https://fal.run',
  '/runway': 'https://api.dev.runwayml.com',
  '/luma': 'https://agents.lumalabs.ai/v1',
  '/ideogram': 'https://api.ideogram.ai',
  '/bfl': 'https://api.bfl.ai',
  '/deepgram': 'https://api.deepgram.com',

  // --- 新增：搜索 & 向量 ---
  '/jina': 'https://api.jina.ai',
  '/tavily': 'https://api.tavily.com',
};

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, x-api-key, x-proxy-key, openai-organization, anthropic-version, anthropic-beta, x-request-id',
};

const MAX_BODY_BYTES = 10 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 3;

const ALLOWED_REQUEST_HEADERS = new Set([
  'accept', 'content-type', 'authorization', 'user-agent',
  'x-api-key', 'openai-organization', 'anthropic-version', 'anthropic-beta', 'x-request-id',
]);

const BLOCKED_RESPONSE_HEADERS = new Set([
  'set-cookie', 'content-length', 'content-encoding', 'transfer-encoding',
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
]);

function jsonError(status, error, requestId) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-Id': requestId,
      ...corsHeaders,
    },
  });
}

function parseAllowedHosts(env) {
  const raw = (env.PROXY_ALLOWED_HOSTS || '').trim();
  if (!raw) return new Set();
  return new Set(raw.split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
}

function isPrivateHostname(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h === 'metadata.google.internal') return true;
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 127 || a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0 || a >= 224) return true;
    return false;
  }
  if (h === '::1' || h.startsWith('[::1]') || h.startsWith('fe80:') || h.startsWith('fd') || h.startsWith('fc')) return true;
  return false;
}

function extractPrefixAndRest(pathname) {
  const prefixes = Object.keys(apiMapping).sort((a, b) => b.length - a.length);
  for (const prefix of prefixes) {
    if (pathname === prefix) return [prefix, ''];
    if (pathname.startsWith(prefix + '/')) return [prefix, pathname.slice(prefix.length)];
  }
  return [null, null];
}

function requireGatewayAuth(request, env, requestId) {
  const expected = env.PROXY_KEY;
  if (!expected) {
    return jsonError(503, 'Gateway key not configured', requestId);
  }
  const provided = request.headers.get('x-proxy-key');
  if (!provided || provided !== expected) {
    return jsonError(401, 'Unauthorized', requestId);
  }
  return null;
}

function buildForwardHeaders(request) {
  const headers = new Headers();
  for (const [key, value] of request.headers.entries()) {
    if (ALLOWED_REQUEST_HEADERS.has(key.toLowerCase())) headers.set(key, value);
  }
  return headers;
}

function cleanResponseHeaders(response, requestId) {
  const headers = new Headers();
  for (const [key, value] of response.headers.entries()) {
    if (!BLOCKED_RESPONSE_HEADERS.has(key.toLowerCase())) headers.set(key, value);
  }
  for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Request-Id', requestId);
  return headers;
}

function checkBodySize(request) {
  const len = request.headers.get('content-length');
  if (len !== null && Number(len) > MAX_BODY_BYTES) return false;
  return true;
}

async function fetchWithTimeout(url, init) {
  const signal = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
  return fetch(url, { ...init, signal });
}

async function fetchAllowlisted(targetUrl, request, allowedHosts, requestId) {
  let current = targetUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch {
      return jsonError(400, 'Invalid URL', requestId);
    }
    if (parsed.protocol !== 'https:') return jsonError(403, 'Only https targets are allowed', requestId);
    if (parsed.username || parsed.password) return jsonError(403, 'URLs with credentials are not allowed', requestId);
    if (parsed.port && parsed.port !== '443') return jsonError(403, 'Non-standard ports are not allowed', requestId);
    const host = parsed.hostname.toLowerCase();
    if (isPrivateHostname(host)) return jsonError(403, 'Private hosts are not allowed', requestId);
    if (!allowedHosts.has(host)) return jsonError(403, 'Host not in allowlist', requestId);

    let response;
    try {
      response = await fetchWithTimeout(current, {
        method: request.method,
        headers: buildForwardHeaders(request),
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        redirect: 'manual',
      });
    } catch {
      return jsonError(502, 'Upstream error', requestId);
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) return new Response(response.body, { status: response.status, headers: cleanResponseHeaders(response, requestId) });
      if (hop === MAX_REDIRECTS) return jsonError(502, 'Too many redirects', requestId);
      try {
        current = new URL(location, current).toString();
      } catch {
        return jsonError(502, 'Invalid redirect', requestId);
      }
      continue;
    }
    return new Response(response.body, { status: response.status, headers: cleanResponseHeaders(response, requestId) });
  }
  return jsonError(502, 'Too many redirects', requestId);
}

export default {
  async fetch(request, env, ctx) {
    const requestId = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now());
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders, 'X-Request-Id': requestId } });
    }

    if (pathname === '/' || pathname === '/index.html') {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('Frontend asset not configured. Deploy with the [assets] section in wrangler.toml.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain', ...corsHeaders },
      });
    }

    if (pathname === '/robots.txt') {
      return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain' } });
    }

    if (pathname === '/health' || pathname === '/ping') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders, 'X-Request-Id': requestId },
      });
    }

    if (!checkBodySize(request)) {
      return jsonError(413, 'Request body too large', requestId);
    }

    if (pathname === '/proxy') {
      const authError = requireGatewayAuth(request, env, requestId);
      if (authError) return authError;
      const targetUrl = url.searchParams.get('url');
      if (!targetUrl) return jsonError(400, 'Missing URL', requestId);
      const allowedHosts = parseAllowedHosts(env);
      if (allowedHosts.size === 0) {
        return jsonError(403, 'Universal proxy is disabled (PROXY_ALLOWED_HOSTS is empty)', requestId);
      }
      return fetchAllowlisted(targetUrl, request, allowedHosts, requestId);
    }

    const [prefix, rest] = extractPrefixAndRest(pathname);
    if (!prefix) {
      return new Response('Not Found', { status: 404, headers: { ...corsHeaders, 'X-Request-Id': requestId } });
    }
    const authError = requireGatewayAuth(request, env, requestId);
    if (authError) return authError;

    const targetUrl = `${apiMapping[prefix]}${rest}${url.search}`;
    try {
      const response = await fetchWithTimeout(targetUrl, {
        method: request.method,
        headers: buildForwardHeaders(request),
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });
      return new Response(response.body, { status: response.status, headers: cleanResponseHeaders(response, requestId) });
    } catch {
      return jsonError(502, 'Upstream error', requestId);
    }
  }
};

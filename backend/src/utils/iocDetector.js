const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]{2,39}$/;
const MD5_RE = /^[a-fA-F0-9]{32}$/;
const SHA1_RE = /^[a-fA-F0-9]{40}$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;
const URL_RE = /^https?:\/\/[^\s]+$/i;
const DOMAIN_RE = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$/;

function isValidIPv4(value) {
  if (!IPV4_RE.test(value)) return false;
  return value.split('.').every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
}

/**
 * Classify a raw indicator string.
 * @param {string} raw
 * @returns {{ type: 'ipv4'|'ipv6'|'md5'|'sha1'|'sha256'|'url'|'domain'|'unknown', value: string }}
 */
function detectIocType(raw) {
  const value = String(raw || '').trim();

  if (isValidIPv4(value)) return { type: 'ipv4', value };
  if (value.includes(':') && IPV6_RE.test(value)) return { type: 'ipv6', value };
  if (URL_RE.test(value)) return { type: 'url', value };
  if (SHA256_RE.test(value)) return { type: 'sha256', value: value.toLowerCase() };
  if (SHA1_RE.test(value)) return { type: 'sha1', value: value.toLowerCase() };
  if (MD5_RE.test(value)) return { type: 'md5', value: value.toLowerCase() };
  if (DOMAIN_RE.test(value)) return { type: 'domain', value: value.toLowerCase() };

  return { type: 'unknown', value };
}

// Regex bank used to extract indicators out of raw log text
const EXTRACT_PATTERNS = {
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  url: /\bhttps?:\/\/[^\s"'<>]+/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
};

/**
 * Pull unique IoCs of every known type out of a block of free-form log text.
 * @param {string} text
 */
function extractIndicatorsFromText(text) {
  const found = { ipv4: new Set(), domain: new Set(), url: new Set(), sha256: new Set(), sha1: new Set(), md5: new Set() };

  for (const [type, regex] of Object.entries(EXTRACT_PATTERNS)) {
    const matches = text.match(regex) || [];
    matches.forEach((m) => found[type].add(m.toLowerCase()));
  }

  // Hashes are hex-overlapping (a sha256 substring can't match md5 length, so no dedup needed across those).
  // Domains regex is greedy and will also match the domain portion inside URLs and IPs; clean up.
  for (const ip of found.ipv4) found.domain.delete(ip);
  for (const url of found.url) {
    try {
      const host = new URL(url).hostname;
      found.domain.delete(host);
    } catch (_) {
      /* ignore malformed URL */
    }
  }

  return {
    ipv4: [...found.ipv4],
    domain: [...found.domain],
    url: [...found.url],
    sha256: [...found.sha256],
    sha1: [...found.sha1],
    md5: [...found.md5],
  };
}

module.exports = { detectIocType, extractIndicatorsFromText, isValidIPv4 };

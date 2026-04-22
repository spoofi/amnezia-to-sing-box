// ─────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────

function base64urlToBytes(b64) {
    let s = b64.replace(/-/g, '+').replace(/_/g, '/');
    const rem = s.length % 4;
    if (rem === 2) s += '==';
    else if (rem === 3) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// Scan for zlib magic bytes (0x78 xx) and inflate
function zlibInflate(bytes) {
    const secondBytes = [0x9C, 0xDA, 0x01, 0x5E];
    for (let i = 0; i < bytes.length - 1; i++) {
        if (bytes[i] === 0x78 && secondBytes.includes(bytes[i + 1])) {
            try {
                return pako.inflate(bytes.subarray(i), { to: 'string' });
            } catch (_) { /* keep scanning */ }
        }
    }
    // Fallback: try raw inflate from byte 0
    try { return pako.inflateRaw(bytes, { to: 'string' }); } catch (_) { }
    // Fallback: plain UTF-8
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

// ─────────────────────────────────────────────
//  WireGuard INI parser
// ─────────────────────────────────────────────

function parseINI(text) {
    const result = { iface: {}, peers: [] };
    let section = null, peer = null;
    for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        if (line === '[Interface]') { section = 'iface'; peer = null; continue; }
        if (line === '[Peer]') { section = 'peer'; peer = {}; result.peers.push(peer); continue; }
        const eq = line.indexOf('=');
        if (eq === -1) continue;
        const k = line.slice(0, eq).trim();
        const v = line.slice(eq + 1).trim();
        if (section === 'iface') result.iface[k] = v;
        else if (section === 'peer' && peer) peer[k] = v;
    }
    return result;
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

function intVal(v, def = 0) {
    if (v == null || v === '') return def;
    const n = parseInt(String(v), 10);
    return isNaN(n) ? def : n;
}

function strVal(v) {
    return (v == null) ? '' : String(v).trim();
}

function parseAllowedIPs(raw) {
    if (!raw) return ['0.0.0.0/0', '::/0'];
    if (Array.isArray(raw)) return raw.map(s => s.trim()).filter(Boolean);
    return String(raw).split(',').map(s => s.trim()).filter(Boolean);
}

function splitEndpoint(raw) {
    if (!raw) return { host: '', port: 0 };
    const i = raw.lastIndexOf(':');
    if (i === -1) return { host: raw, port: 0 };
    return { host: raw.slice(0, i), port: intVal(raw.slice(i + 1)) };
}

function makeTag(description, hostname, index) {
    const src = description || hostname || '';
    const base = src
        .toLowerCase()
        .replace(/[^a-z0-9.]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 40)
        || 'awg-tunnel';
    return index > 0 ? `${base}-${index + 1}` : base;
}

// ─────────────────────────────────────────────
//  AWG2 container from vpn:// key (amnezia-awg2)
//  container.awg has flat params; last_config is JSON
// ─────────────────────────────────────────────

function buildFromAWG2(container, topData, index) {
    const awg = container.awg || {};
    let lc = {};
    try { lc = JSON.parse(awg.last_config || '{}'); } catch (_) { }

    const jc = intVal(awg.Jc ?? lc.Jc);
    const jmin = intVal(awg.Jmin ?? lc.Jmin);
    const jmax = intVal(awg.Jmax ?? lc.Jmax);
    const s1 = intVal(awg.S1 ?? lc.S1);
    const s2 = intVal(awg.S2 ?? lc.S2);
    const s3 = intVal(awg.S3 ?? lc.S3);
    const s4 = intVal(awg.S4 ?? lc.S4);
    const h1 = strVal(awg.H1 ?? lc.H1);
    const h2 = strVal(awg.H2 ?? lc.H2);
    const h3 = strVal(awg.H3 ?? lc.H3);
    const h4 = strVal(awg.H4 ?? lc.H4);
    const i1 = strVal(awg.I1 ?? lc.I1);
    const i2 = strVal(awg.I2 ?? lc.I2);
    const i3 = strVal(awg.I3 ?? lc.I3);
    const i4 = strVal(awg.I4 ?? lc.I4);
    const i5 = strVal(awg.I5 ?? lc.I5);

    const clientIp = strVal(lc.client_ip ?? '');
    const address = clientIp
        ? (clientIp.includes('/') ? [clientIp] : [`${clientIp}/32`])
        : [];

    const serverHost = strVal(lc.hostName ?? topData.hostName ?? '');
    const serverPort = intVal(lc.port ?? awg.port);

    return {
        type: 'awg',
        tag: makeTag(topData.description, topData.hostName, index),
        address,
        private_key: strVal(lc.client_priv_key),
        mtu: intVal(lc.mtu, 1420),
        jc, jmin, jmax,
        s1, s2, s3, s4,
        h1, h2, h3, h4,
        i1, i2, i3, i4, i5,
        peers: [{
            public_key: strVal(lc.server_pub_key),
            preshared_key: strVal(lc.psk_key ?? ''),
            allowed_ips: parseAllowedIPs(lc.allowed_ips),
            address: serverHost,
            port: serverPort,
            persistent_keepalive_interval: intVal(lc.persistent_keep_alive, 25),
        }],
    };
}

// ─────────────────────────────────────────────
//  AWG2 INI config (raw [Interface]/[Peer] text)
// ─────────────────────────────────────────────

function buildFromINI(text) {
    const ini = parseINI(text);
    const iface = ini.iface;

    if (!iface.PrivateKey) throw new Error('PrivateKey not found in [Interface] section.');
    if (ini.peers.length === 0) throw new Error('[Peer] section not found.');

    const addrRaw = strVal(iface.Address);
    const address = addrRaw
        ? addrRaw.split(',').map(s => s.trim()).filter(Boolean)
        : [];

    const peers = ini.peers.map(p => {
        const ep = splitEndpoint(p.Endpoint);
        return {
            public_key: strVal(p.PublicKey),
            preshared_key: strVal(p.PresharedKey ?? ''),
            allowed_ips: parseAllowedIPs(p.AllowedIPs),
            address: ep.host,
            port: ep.port,
            persistent_keepalive_interval: intVal(p.PersistentKeepalive, 25),
        };
    });

    // Derive tag from first peer's endpoint hostname
    const firstHost = peers[0]?.address ?? '';
    const tag = makeTag('', firstHost, 0);

    return {
        type: 'awg',
        tag,
        address,
        private_key: strVal(iface.PrivateKey),
        mtu: intVal(iface.MTU, 1420),
        jc: intVal(iface.Jc),
        jmin: intVal(iface.Jmin),
        jmax: intVal(iface.Jmax),
        s1: intVal(iface.S1),
        s2: intVal(iface.S2),
        s3: intVal(iface.S3),
        s4: intVal(iface.S4),
        h1: strVal(iface.H1),
        h2: strVal(iface.H2),
        h3: strVal(iface.H3),
        h4: strVal(iface.H4),
        i1: strVal(iface.I1),
        i2: strVal(iface.I2),
        i3: strVal(iface.I3),
        i4: strVal(iface.I4),
        i5: strVal(iface.I5),
        peers,
    };
}

// ─────────────────────────────────────────────
//  Main conversion — auto-detects input format
// ─────────────────────────────────────────────

function convert() {
    hideAlerts();
    const input = document.getElementById('key-input').value.trim();

    if (!input) {
        showError('Empty input', 'Paste a vpn:// key or an AmneziaWG native format config.');
        return;
    }

    // ── Native AWG format ────────────────────────
    if (!input.startsWith('vpn://')) {
        if (input.startsWith('[Interface]') || input.startsWith('[Peer]')) {
            let result;
            try {
                result = buildFromINI(input);
            } catch (e) {
                showError('Failed to parse AWG 2.0 native format', e.message);
                return;
            }
            renderOutput([result]);
            showOK('Done! AWG 2.0 native format config converted successfully.');
        } else {
            showError(
                'Unknown format',
                'Expected a vpn:// key or a native AWG config.\n' +
                `Got: "${input.slice(0, 60)}…"`
            );
        }
        return;
    }

    // ── vpn:// key ──────────────────────────────
    if (typeof pako === 'undefined') {
        showError('Initialization error', 'pako library failed to load. Check your internet connection and reload the page.');
        return;
    }

    let data;
    try {
        const b64 = input.slice('vpn://'.length).trim();
        const bytes = base64urlToBytes(b64);
        const json = zlibInflate(bytes);
        data = JSON.parse(json);
    } catch (e) {
        showError('Failed to decode key', e.message);
        return;
    }

    const containers = Array.isArray(data.containers) ? data.containers : [];
    if (containers.length === 0) {
        showError('No containers found', 'Make sure the key was exported from AmneziaVPN.');
        return;
    }

    const endpoints = [];
    const skipped = [];

    let idx = 0;
    for (const c of containers) {
        if (c.awg && typeof c.awg === 'object') {
            endpoints.push(buildFromAWG2(c, data, idx++));
        } else {
            skipped.push(strVal(c.container) || '(unknown)');
        }
    }

    if (endpoints.length === 0) {
        showError(
            'No AWG configs found',
            `Containers in key: ${skipped.join(', ')}. Only containers with an "awg" object are supported.`
        );
        return;
    }

    renderOutput(endpoints);
    const count = endpoints.length;
    const msg = `Done! Converted ${count} ${count === 1 ? 'endpoint' : 'endpoints'}.`;
    if (skipped.length > 0) {
        showWarn(msg + ` Skipped: ${skipped.join(', ')}.`);
    } else {
        showOK(msg);
    }
}

function renderOutput(endpoints) {
    const result = endpoints.length === 1 ? endpoints[0] : endpoints;
    document.getElementById('output').value = JSON.stringify(result, null, 2);
    const n = endpoints.length;
    document.getElementById('badge-count').textContent = `${n} ${n === 1 ? 'endpoint' : 'endpoints'}`;
    document.getElementById('output-section').classList.add('show');
}

// ─────────────────────────────────────────────
//  Actions
// ─────────────────────────────────────────────

function copyResult() {
    const text = document.getElementById('output').value;
    const btn = document.getElementById('btn-copy');
    navigator.clipboard.writeText(text).then(() => {
        btn.classList.add('copied');
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`;
        }, 2200);
    }).catch(() => {
        const ta = document.getElementById('output');
        ta.select();
        document.execCommand('copy');
        showOK('Copied to clipboard.');
    });
}

function formatJSON() {
    const ta = document.getElementById('output');
    try {
        ta.value = JSON.stringify(JSON.parse(ta.value), null, 2);
        showOK('JSON formatted.');
    } catch (e) {
        showError('Invalid JSON', e.message);
    }
}

function clearAll() {
    document.getElementById('key-input').value = '';
    document.getElementById('output').value = '';
    document.getElementById('output-section').classList.remove('show');
    hideAlerts();
}

// ─────────────────────────────────────────────
//  Alerts
// ─────────────────────────────────────────────

function showError(title, detail) {
    document.getElementById('alert-error-title').textContent = title;
    document.getElementById('alert-error-detail').textContent = detail || '';
    document.getElementById('alert-error').classList.add('show');
    document.getElementById('alert-ok').classList.remove('show');
    document.getElementById('alert-warn').classList.remove('show');
}

function showOK(msg) {
    document.getElementById('alert-ok-text').textContent = msg;
    document.getElementById('alert-ok').classList.add('show');
    document.getElementById('alert-error').classList.remove('show');
    document.getElementById('alert-warn').classList.remove('show');
}

function closeAlert(id) {
    document.getElementById(id).classList.remove('show');
}

function showWarn(msg) {
    document.getElementById('alert-warn-text').textContent = msg;
    document.getElementById('alert-warn').classList.add('show');
    document.getElementById('alert-error').classList.remove('show');
    document.getElementById('alert-ok').classList.remove('show');
}

function hideAlerts() {
    ['alert-error', 'alert-ok', 'alert-warn'].forEach(id =>
        document.getElementById(id).classList.remove('show')
    );
}

// Allow Ctrl+Enter to convert
document.getElementById('key-input').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') convert();
});

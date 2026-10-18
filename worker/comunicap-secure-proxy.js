/**
 * comunicap-secure-proxy — Cloudflare Worker
 * ════════════════════════════════════════════════════════════════════
 * Cambios en esta versión (rama fix/auth-admin):
 *  - /admin/db-write y /admin/picto-db-write ya NO aceptan adminKey.
 *    Exigen un access_token de Supabase Auth del administrador global
 *    (Authorization: Bearer <token>). El Worker lo valida contra
 *    Supabase y verifica que el usuario sea role = admin y status = active
 *    en hadrion_users. La clave ADMIN_API_KEY ya no se usa: borrarla.
 *  - CORS permite el header Authorization (sin esto el navegador bloquea
 *    las peticiones del panel).
 *
 * DESPLIEGUE:
 *  1. Cloudflare → Workers & Pages → comunicap-secure-proxy → Edit code.
 *     Reemplazar todo el contenido por este archivo y "Deploy".
 *  2. Settings → Variables and Secrets: eliminar ADMIN_API_KEY.
 *  3. Verificar que existan: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
 *     PICTO_SUPABASE_URL, PICTO_SUPABASE_SERVICE_ROLE_KEY y, si ya
 *     se creó, el KV binding RATE_LIMIT_KV.
 * ════════════════════════════════════════════════════════════════════
 */

// Orígenes permitidos a llamar este Worker (ajustar si cambia el dominio)
const ALLOWED_ORIGINS = [
  'https://comunipro2026-oss.github.io',
  'http://localhost:3000',
  'http://127.0.0.1:5500'
];

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
  });
}

async function sbFetchRaw(baseUrl, serviceKey, path, opts) {
  return fetch(`${baseUrl}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
      ...(opts && opts.headers ? opts.headers : {})
    }
  });
}

async function sbFetch(env, path, opts) {
  return sbFetchRaw(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, path, opts);
}

async function pcFetch(env, path, opts) {
  return sbFetchRaw(env.PICTO_SUPABASE_URL, env.PICTO_SUPABASE_SERVICE_ROLE_KEY, path, opts);
}

// ── RATE LIMITING ─────────────────────────────────────────────────────
// Contador simple por ventana fija usando Workers KV. Si RATE_LIMIT_KV no
// está bindeado, deja pasar todo (fail-open).
async function checkRateLimit(env, key, limit, windowSeconds) {
  if (!env.RATE_LIMIT_KV) return true;
  try {
    const now = Math.floor(Date.now() / 1000);
    const bucket = Math.floor(now / windowSeconds);
    const kvKey = `rl:${key}:${bucket}`;
    const current = parseInt((await env.RATE_LIMIT_KV.get(kvKey)) || '0', 10);
    if (current >= limit) return false;
    await env.RATE_LIMIT_KV.put(kvKey, String(current + 1), { expirationTtl: windowSeconds * 2 });
    return true;
  } catch (e) {
    console.error('checkRateLimit error (fail-open):', e.message);
    return true;
  }
}

// Tope de caracteres razonable para strings que llegan del cliente.
function tooLong(str, max) {
  return typeof str === 'string' && str.length > max;
}

// Tablas a las que /register-session tiene permitido escribir.
const SESSION_TABLES = new Set(['licencias2']);

// Tablas a las que /admin/db-write tiene permitido escribir (panel comunicap-admin).
const ADMIN_TABLES = new Set(['licencias2', 'organizaciones', 'pictogramas', 'org_usuarios', 'hadrion_organizaciones', 'hadrion_users']);

// Tablas del proyecto PictoCrisis que /admin/picto-db-write puede escribir.
const PICTO_ADMIN_TABLES = new Set(['organizaciones', 'org_admins', 'policias']);

/* ── Autenticación del administrador global de Hadrion ──────────────
   1) El token debe ser un access_token válido de Supabase Auth.
   2) El usuario debe tener, en hadrion_users, role = 'admin', status =
      'active' y no estar borrado (deletedAt null). */
async function verifyHadrionAdmin(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return { ok: false, status: 401, error: 'Sesión requerida' };

  const ures = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${token}` }
  });
  if (!ures.ok) return { ok: false, status: 401, error: 'Sesión inválida' };
  const user = await ures.json().catch(() => null);
  if (!user || !user.id) return { ok: false, status: 401, error: 'Sesión inválida' };

  const pres = await sbFetch(env,
    `hadrion_users?auth_user_id=eq.${encodeURIComponent(user.id)}&deletedAt=is.null&select=role,status`,
    { method: 'GET' });
  if (!pres.ok) return { ok: false, status: 502, error: 'Sin conexión al servidor' };
  const rows = await pres.json().catch(() => []);
  if (!Array.isArray(rows) || !rows.length || rows[0].role !== 'admin' || rows[0].status !== 'active') {
    return { ok: false, status: 403, error: 'No autorizado' };
  }
  return { ok: true, user };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }
    if (request.method !== 'POST') {
      return json({ error: 'Método no permitido' }, 405, origin);
    }

    const url = new URL(request.url);
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ error: 'JSON inválido' }, 400, origin);
    }

    // ── Rate limit general por IP ──
    const ip = request.headers.get('CF-Connecting-IP') || 'sin-ip';
    const ipOk = await checkRateLimit(env, `ip:${ip}`, 60, 60);
    if (!ipOk) {
      return json({ error: 'Demasiados intentos. Esperá un minuto y probá de nuevo.' }, 429, origin);
    }

    // ── Rate limit extra por código en rutas sensibles ──
    const SENSITIVE_ROUTES = new Set(['/verify-device', '/take-control', '/register-session', '/switch-device']);
    if (SENSITIVE_ROUTES.has(url.pathname)) {
      const code = body && (body.code || body.clave);
      if (code) {
        const codeOk = await checkRateLimit(env, `code:${String(code).toUpperCase()}`, 10, 300);
        if (!codeOk) {
          return json({ error: 'Demasiados intentos con este código. Esperá unos minutos.' }, 429, origin);
        }
      }
    }

    try {
      switch (url.pathname) {
        case '/verify-device':
          return await handleVerifyDevice(body, env, origin);
        case '/switch-device':
          return await handleSwitchDevice(body, env, origin);
        case '/take-control':
          return await handleTakeControl(body, env, origin);
        case '/register-session':
          return await handleRegisterSession(body, env, origin);
        case '/ceo-picto-save':
          return await handleCeoPictoSave(body, env, origin);
        case '/ceo-picto-delete':
          return await handleCeoPictoDelete(body, env, origin);
        case '/admin/db-write': {
          const adm = await verifyHadrionAdmin(request, env);
          if (!adm.ok) return json({ error: adm.error }, adm.status, origin);
          return await handleAdminWrite(body, env, origin);
        }
        case '/admin/picto-db-write': {
          const adm = await verifyHadrionAdmin(request, env);
          if (!adm.ok) return json({ error: adm.error }, adm.status, origin);
          return await handlePictoAdminWrite(body, env, origin);
        }
        default:
          return json({ error: 'Ruta no encontrada' }, 404, origin);
      }
    } catch (e) {
      console.error('Error no controlado en', url.pathname, ':', e.message, e.stack);
      return json({ error: 'Error interno del servidor' }, 500, origin);
    }
  }
};

/* ── /verify-device ── */
async function handleVerifyDevice(body, env, origin) {
  const { code, deviceId } = body;
  if (!code || !deviceId) return json({ error: 'Faltan datos' }, 400, origin);
  if (tooLong(code, 40) || tooLong(deviceId, 200)) {
    return json({ error: 'Datos inválidos' }, 400, origin);
  }

  const res = await sbFetch(env,
    `licencias2?clave=eq.${encodeURIComponent(code)}&select=clave,plan,activa,fecha_vencimiento,dispositivos,limite_pacientes,nombre,apellido,edit_habilitado`,
    { method: 'GET' });
  if (!res.ok) return json({ error: 'Sin conexión al servidor' }, 502, origin);
  const data = await res.json();
  if (!data.length) return json({ error: 'Código no encontrado' }, 404, origin);
  const lic = data[0];
  if (!lic.activa) return json({ error: 'Esta licencia está suspendida' }, 403, origin);
  if (lic.fecha_vencimiento) {
    const exp = new Date(lic.fecha_vencimiento + 'T23:59:59');
    if (exp < new Date()) {
      return json({ error: 'Esta licencia venció el ' + lic.fecha_vencimiento.split('-').reverse().join('/') }, 403, origin);
    }
  }

  if (lic.plan !== 'ceo') {
    const dispositivos = Array.isArray(lic.dispositivos) ? lic.dispositivos : [];
    const limite = lic.plan === 'clinica' ? (lic.limite_pacientes || 15) : 1;
    if (!dispositivos.includes(deviceId)) {
      if (dispositivos.length >= limite) {
        const msg = lic.plan === 'clinica'
          ? `Este código ya está en uso en ${dispositivos.length} dispositivo(s). Límite del plan: ${limite}.`
          : 'Este código ya está siendo usado en otro dispositivo. Cada código es personal e intransferible.';
        return json({ error: msg }, 409, origin);
      }
      const nuevos = [...dispositivos, deviceId];
      await sbFetch(env, `licencias2?clave=eq.${encodeURIComponent(code)}`, {
        method: 'PATCH',
        headers: { Prefer: 'return=minimal' },
        body: JSON.stringify({ dispositivos: nuevos })
      });
    }
  }

  const nombreCompleto = [lic.nombre, lic.apellido].filter(Boolean).join(' ').trim();
  return json({
    ok: true,
    code: lic.clave,
    plan: lic.plan,
    expiry: lic.fecha_vencimiento || null,
    nombre: nombreCompleto,
    editHabilitado: lic.plan === 'ceo' ? true : (lic.edit_habilitado === true)
  }, 200, origin);
}

/* ── /switch-device ── */
async function handleSwitchDevice(body, env, origin) {
  const { code, deviceId } = body;
  if (!code || !deviceId) return json({ error: 'Faltan datos' }, 400, origin);
  if (tooLong(code, 40) || tooLong(deviceId, 200)) {
    return json({ error: 'Datos inválidos' }, 400, origin);
  }

  const res = await sbFetch(env,
    `licencias2?clave=eq.${encodeURIComponent(code)}&select=clave,plan,activa,fecha_vencimiento,nombre,apellido,edit_habilitado`,
    { method: 'GET' });
  if (!res.ok) return json({ error: 'Sin conexión al servidor' }, 502, origin);
  const data = await res.json();
  if (!data.length) return json({ error: 'Código no encontrado' }, 404, origin);
  const lic = data[0];
  if (!lic.activa) return json({ error: 'Esta licencia está suspendida' }, 403, origin);
  if (lic.fecha_vencimiento) {
    const exp = new Date(lic.fecha_vencimiento + 'T23:59:59');
    if (exp < new Date()) {
      return json({ error: 'Esta licencia venció el ' + lic.fecha_vencimiento.split('-').reverse().join('/') }, 403, origin);
    }
  }

  const token = crypto.randomUUID();
  const patch = await sbFetch(env, `licencias2?clave=eq.${encodeURIComponent(code)}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=minimal' },
    body: JSON.stringify({ dispositivos: [deviceId], sesion_token: token, sesion_ts: new Date().toISOString() })
  });
  if (!patch.ok) return json({ error: 'No se pudo cambiar el dispositivo' }, 502, origin);

  const nombreCompleto = [lic.nombre, lic.apellido].filter(Boolean).join(' ').trim();
  return json({
    ok: true,
    code: lic.clave,
    plan: lic.plan,
    expiry: lic.fecha_vencimiento || null,
    nombre: nombreCompleto,
    editHabilitado: lic.plan === 'ceo' ? true : (lic.edit_habilitado === true),
    token
  }, 200, origin);
}

/* ── /take-control ── */
async function handleTakeControl(body, env, origin) {
  const { code } = body;
  if (!code) return json({ error: 'Falta code' }, 400, origin);
  if (tooLong(code, 40)) return json({ error: 'Datos inválidos' }, 400, origin);
  const token = crypto.randomUUID();
  const res = await sbFetch(env, `licencias2?clave=eq.${encodeURIComponent(code)}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=minimal' },
    body: JSON.stringify({ sesion_token: token })
  });
  if (!res.ok) return json({ error: 'No se pudo actualizar la sesión' }, 502, origin);
  return json({ ok: true, token }, 200, origin);
}

/* ── /register-session ── */
async function handleRegisterSession(body, env, origin) {
  const { clave, tabla, campoId } = body;
  if (!clave || !tabla || !campoId) return json({ error: 'Faltan datos' }, 400, origin);
  if (tooLong(clave, 40)) return json({ error: 'Datos inválidos' }, 400, origin);
  if (!SESSION_TABLES.has(tabla)) return json({ error: 'Tabla no permitida' }, 400, origin);
  const token = crypto.randomUUID();
  await sbFetch(env, `${tabla}?${campoId}=eq.${encodeURIComponent(clave)}`, {
    method: 'PATCH',
    headers: { Prefer: 'return=minimal' },
    body: JSON.stringify({ sesion_token: token, sesion_ts: new Date().toISOString() })
  });
  return json({ ok: true, token }, 200, origin);
}

/* ── Helper: verificar server-side que el code es CEO ── */
async function assertCeo(code, env) {
  const res = await sbFetch(env, `licencias2?clave=eq.${encodeURIComponent(code)}&select=plan`, { method: 'GET' });
  if (!res.ok) return false;
  const data = await res.json();
  return data.length > 0 && data[0].plan === 'ceo';
}

/* ── /ceo-picto-save ── */
async function handleCeoPictoSave(body, env, origin) {
  const { code, picto } = body;
  if (!code || !picto || !picto.etiqueta || !picto.categoria) {
    return json({ error: 'Faltan datos' }, 400, origin);
  }
  if (tooLong(code, 40) || tooLong(picto.etiqueta, 80) || tooLong(picto.categoria, 40)) {
    return json({ error: 'Datos inválidos' }, 400, origin);
  }
  if (!(await assertCeo(code, env))) return json({ error: 'No autorizado' }, 403, origin);

  const existing = await sbFetch(env,
    `pictogramas?app=eq.comunicap&etiqueta=eq.${encodeURIComponent(picto.etiqueta)}&categoria=eq.${encodeURIComponent(picto.categoria)}`,
    { method: 'GET' });
  const data = await existing.json();

  if (data && data.length > 0) {
    await sbFetch(env, `pictogramas?id=eq.${data[0].id}`, {
      method: 'PATCH',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ emoji: picto.emoji, etiqueta: picto.etiqueta, activo: true })
    });
  } else {
    await sbFetch(env, `pictogramas`, {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({
        app: 'comunicap', emoji: picto.emoji, etiqueta: picto.etiqueta,
        categoria: picto.categoria, orden: picto.orden || 99, activo: true
      })
    });
  }
  return json({ ok: true }, 200, origin);
}

/* ── /ceo-picto-delete ── */
async function handleCeoPictoDelete(body, env, origin) {
  const { code, etiqueta, categoria } = body;
  if (!code || !etiqueta || !categoria) return json({ error: 'Faltan datos' }, 400, origin);
  if (tooLong(code, 40) || tooLong(etiqueta, 80) || tooLong(categoria, 40)) {
    return json({ error: 'Datos inválidos' }, 400, origin);
  }
  if (!(await assertCeo(code, env))) return json({ error: 'No autorizado' }, 403, origin);

  await sbFetch(env,
    `pictogramas?app=eq.comunicap&etiqueta=eq.${encodeURIComponent(etiqueta)}&categoria=eq.${encodeURIComponent(categoria)}`,
    { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ activo: false }) });
  return json({ ok: true }, 200, origin);
}

/* ── /admin/db-write (requiere admin verificado por JWT) ── */
async function handleAdminWrite(body, env, origin) {
  const { path, method, body: payload } = body;
  if (!path || !method) return json({ error: 'Faltan datos' }, 400, origin);
  if (!['POST', 'PATCH', 'DELETE'].includes(method)) {
    return json({ error: 'Método no permitido' }, 400, origin);
  }
  const table = String(path).split('?')[0];
  if (!ADMIN_TABLES.has(table)) return json({ error: 'Tabla no permitida' }, 400, origin);

  const prefer = method === 'DELETE' ? 'return=minimal' : (body.prefer || 'return=representation');
  const res = await sbFetch(env, path, {
    method,
    headers: { Prefer: prefer },
    body: method !== 'DELETE' ? JSON.stringify(payload || {}) : undefined
  });

  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) {
    const msg = (data && (data.message || data.hint || data.error)) || ('Error ' + res.status);
    return json({ error: msg }, res.status, origin);
  }
  return json({ ok: true, data }, 200, origin);
}

/* ── /admin/picto-db-write (requiere admin verificado por JWT) ── */
async function handlePictoAdminWrite(body, env, origin) {
  const { path, method, body: payload } = body;
  if (!path || !method) return json({ error: 'Faltan datos' }, 400, origin);
  if (!['POST', 'PATCH', 'DELETE'].includes(method)) {
    return json({ error: 'Método no permitido' }, 400, origin);
  }
  const table = String(path).split('?')[0];
  if (!PICTO_ADMIN_TABLES.has(table)) return json({ error: 'Tabla no permitida' }, 400, origin);

  const prefer = method === 'DELETE' ? 'return=minimal' : (body.prefer || 'return=representation');
  const res = await pcFetch(env, path, {
    method,
    headers: { Prefer: prefer },
    body: method !== 'DELETE' ? JSON.stringify(payload || {}) : undefined
  });

  let data2 = null;
  try { data2 = await res.json(); } catch (e) {}
  if (!res.ok) {
    const msg = (data2 && (data2.message || data2.hint || data2.error)) || ('Error ' + res.status);
    return json({ error: msg }, res.status, origin);
  }
  return json({ ok: true, data: data2 }, 200, origin);
}

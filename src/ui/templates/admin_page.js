         const ADMIN_ROOT = '/_apiproxy/admin';
         const ADMIN_ACCESS_TOKEN_STORAGE = 'apiproxy_admin_access_token_v1';
         let currentKey = '';
        let pendingDeleteHeaderName = '';
        let configValidateTimer = null;
        let sandboxTemplateKey = '';
        let outboundRuleDrafts = [];
        let inboundRuleDrafts = [];
        let currentTabName = 'overview';
        const dirtyTabs = new Set();
        let liveLogStreamAbortController = null;
        let liveLogReconnectTimer = null;
        let liveLogShouldReconnect = false;
        const LIVE_LOG_MAX_CHARS = 200000;
         const SANDBOX_TEMPLATES = {
           status_page: { label: 'GET /_apiproxy', method: 'GET', path: '/_apiproxy', auth_mode: 'none', headers: {}, body: null },
           request_passthrough: {
             label: 'POST /_apiproxy/request',
             method: 'POST',
             path: '/_apiproxy/request',
             auth_mode: 'proxy_key',
             headers: { 'Content-Type': 'application/json', 'X-Proxy-Host': 'https://httpbin.org' },
             body: { upstream: { method: 'GET', url: '/json' } },
           },
           rotate_proxy: { label: 'POST /_apiproxy/keys/proxy/rotate', method: 'POST', path: '/_apiproxy/keys/proxy/rotate', auth_mode: 'proxy_key', headers: {}, body: null },
           rotate_issuer: { label: 'POST /_apiproxy/keys/issuer/rotate', method: 'POST', path: '/_apiproxy/keys/issuer/rotate', auth_mode: 'issuer_key', headers: {}, body: null },
           rotate_admin_public: { label: 'POST /_apiproxy/keys/admin/rotate', method: 'POST', path: '/_apiproxy/keys/admin/rotate', auth_mode: 'admin_key', headers: {}, body: null },
           admin_version: { label: 'GET /_apiproxy/admin/version', method: 'GET', path: '/_apiproxy/admin/version', auth_mode: 'admin_token', headers: {}, body: null },
           admin_keys_get: { label: 'GET /_apiproxy/admin/keys', method: 'GET', path: '/_apiproxy/admin/keys', auth_mode: 'admin_token', headers: {}, body: null },
           admin_rotate_proxy: { label: 'POST /_apiproxy/admin/keys/proxy/rotate', method: 'POST', path: '/_apiproxy/admin/keys/proxy/rotate', auth_mode: 'admin_token', headers: {}, body: null },
           admin_rotate_target_auth: { label: 'POST /_apiproxy/admin/keys/issuer/rotate', method: 'POST', path: '/_apiproxy/admin/keys/issuer/rotate', auth_mode: 'admin_token', headers: {}, body: null },
           admin_rotate_admin: { label: 'POST /_apiproxy/admin/keys/admin/rotate', method: 'POST', path: '/_apiproxy/admin/keys/admin/rotate', auth_mode: 'admin_token', headers: {}, body: null },
           admin_config_get: { label: 'GET /_apiproxy/admin/config', method: 'GET', path: '/_apiproxy/admin/config', auth_mode: 'admin_token', headers: {}, body: null },
           admin_config_put: {
             label: 'PUT /_apiproxy/admin/config',
             method: 'PUT',
             path: '/_apiproxy/admin/config',
             auth_mode: 'admin_token',
             headers: { 'Content-Type': 'text/yaml' },
             body: 'targetHost: null\\ntransform:\\n  enabled: true\\n  defaultExpr: \"\"\\n  fallback: passthrough\\n  rules: []\\nheader_forwarding:\\n  mode: blacklist\\n  names:\\n    - connection\\n    - host\\n    - content-length\\n    - x-proxy-key\\n    - x-admin-key\\n    - x-issuer-key\\n    - x-proxy-host',
           },
           admin_config_validate: {
             label: 'POST /_apiproxy/admin/config/validate',
             method: 'POST',
             path: '/_apiproxy/admin/config/validate',
             auth_mode: 'admin_token',
             headers: { 'Content-Type': 'text/yaml' },
             body: 'targetHost: null\\ntransform:\\n  enabled: true\\n  defaultExpr: \"\"\\n  fallback: passthrough\\n  rules: []',
            },
           admin_config_test_rule: {
             label: 'POST /_apiproxy/admin/config/test-rule',
             method: 'POST',
             path: '/_apiproxy/admin/config/test-rule',
             auth_mode: 'admin_token',
             headers: { 'Content-Type': 'application/json' },
             body: { sample: { status: 500, headers: { 'content-type': 'application/json' }, type: 'json', body: { error: 'bad' } } },
           },
           admin_debug_get: { label: 'GET /_apiproxy/admin/debug', method: 'GET', path: '/_apiproxy/admin/debug', auth_mode: 'admin_token', headers: {}, body: null },
           admin_debug_enable: { label: 'PUT /_apiproxy/admin/debug', method: 'PUT', path: '/_apiproxy/admin/debug', auth_mode: 'admin_token', headers: { 'Content-Type': 'application/json' }, body: { enabled: true, ttl_seconds: 3600 } },
           admin_debug_disable: { label: 'DELETE /_apiproxy/admin/debug', method: 'DELETE', path: '/_apiproxy/admin/debug', auth_mode: 'admin_token', headers: {}, body: null },
           admin_debug_last: { label: 'GET /_apiproxy/admin/debug/last', method: 'GET', path: '/_apiproxy/admin/debug/last', auth_mode: 'admin_token', headers: {}, body: null },
           admin_debug_secret_put: { label: 'PUT /_apiproxy/admin/debug/loggingSecret', method: 'PUT', path: '/_apiproxy/admin/debug/loggingSecret', auth_mode: 'admin_token', headers: { 'Content-Type': 'application/json' }, body: { value: 'example' } },
           admin_debug_secret_get: { label: 'GET /_apiproxy/admin/debug/loggingSecret', method: 'GET', path: '/_apiproxy/admin/debug/loggingSecret', auth_mode: 'admin_token', headers: {}, body: null },
           admin_debug_secret_delete: { label: 'DELETE /_apiproxy/admin/debug/loggingSecret', method: 'DELETE', path: '/_apiproxy/admin/debug/loggingSecret', auth_mode: 'admin_token', headers: {}, body: null },
           admin_headers_get: { label: 'GET /_apiproxy/admin/headers', method: 'GET', path: '/_apiproxy/admin/headers', auth_mode: 'admin_token', headers: {}, body: null },
           admin_headers_put: { label: 'PUT /_apiproxy/admin/headers/authorization', method: 'PUT', path: '/_apiproxy/admin/headers/authorization', auth_mode: 'admin_token', headers: { 'Content-Type': 'application/json' }, body: { value: 'Bearer token' } },
           admin_headers_delete: { label: 'DELETE /_apiproxy/admin/headers/authorization', method: 'DELETE', path: '/_apiproxy/admin/headers/authorization', auth_mode: 'admin_token', headers: {}, body: null },
           admin_outbound_get: { label: 'GET /_apiproxy/admin/key-rotation-config', method: 'GET', path: '/_apiproxy/admin/key-rotation-config', auth_mode: 'admin_token', headers: {}, body: null },
         };
         const SANDBOX_API_PREFIX = '/_apiproxy';
        const SANDBOX_REDACT_HEADERS = new Set([
          'authorization',
          'proxy-authorization',
          'cookie',
          'set-cookie',
          'x-proxy-key',
          'x-admin-key',
          'x-issuer-key',
        ]);
        const UI_DEBUG = (() => {
          try {
            const params = new URLSearchParams(window.location.search || '');
            return params.get('debug') === 'true';
          } catch {
            return false;
          }
        })();

        function el(id) { return document.getElementById(id); }
        function bindOnce(id, handler) {
          const node = el(id);
          if (!node) return;
          if (node.dataset.bound === '1') return;
          node.addEventListener('click', handler);
          node.dataset.bound = '1';
        }
         function setOutput(id, data) {
           const node = el(id);
           if (!node) return;
           node.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
         }
        function htmlEscape(value) {
          return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
        }
        function renderHeaderList(prefix, options) {
          const label = options?.label || 'Headers';
          const helpText = options?.helpText || 'YAML-style: Header-Name: value per line';
          const disabled = !!options?.disabled;
          const rows = options?.rows || 4;
          const placeholder = options?.placeholder || 'Header-Name: value';
          const value = options?.value || '';
          return ''
            + '<div style="display:flex;justify-content:space-between;align-items:center;margin:10px 0 4px;">'
            + '<label for="' + prefix + '-headers">' + htmlEscape(label) + '</label>'
            + '<a href="#" id="' + prefix + '-headers-toggle" style="font-size:12px;text-decoration:underline;">hide</a>'
            + '</div>'
            + '<div id="' + prefix + '-headers-help" style="font-size:12px;color:#64748b;margin-top:-2px;margin-bottom:4px;">' + htmlEscape(helpText) + '</div>'
            + '<div id="' + prefix + '-headers-wrap">'
            + '<textarea id="' + prefix + '-headers" rows="' + rows + '" placeholder="' + htmlEscape(placeholder) + '" ' + (disabled ? 'disabled ' : '')
            + 'style="width:100%;max-width:740px;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;' + (disabled ? 'background:#f8fafc;' : '') + '">' + htmlEscape(value) + '</textarea>'
            + '</div>';
        }
        function renderSecretStorage(prefix, options) {
          const label = options?.label || 'Secret';
          const helpText = options?.helpText || '';
          const placeholder = options?.placeholder || '';
          const inputId = options?.inputId || (prefix + '-secret');
          const value = options?.value || '';
          const tsId = options?.timestampFormatId || '';
          const tsLabel = options?.timestampFormatLabel || 'Timestamp format';
          const tsValue = options?.timestampFormatValue || 'epoch_ms';
          const tsHelp = options?.timestampFormatHelp || '';
          const buttons = Array.isArray(options?.buttons) ? options.buttons : [];
          return ''
            + '<label for="' + inputId + '" style="display:block;margin:10px 0 4px;">' + htmlEscape(label) + '</label>'
            + '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">'
            + '<input id="' + inputId + '" type="password" placeholder="' + htmlEscape(placeholder) + '" value="' + htmlEscape(value) + '"'
            + ' style="width:100%;max-width:620px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
            + '<a href="#" id="' + prefix + '-secret-toggle" style="font-size:12px;text-decoration:underline;">show</a>'
            + '</div>'
            + (helpText ? '<div style="font-size:12px;color:#64748b;margin-top:4px;">' + htmlEscape(helpText) + '</div>' : '')
            + (tsId
              ? ('<label for="' + htmlEscape(tsId) + '" style="display:block;margin:10px 0 4px;">' + htmlEscape(tsLabel) + '</label>'
                + '<select id="' + htmlEscape(tsId) + '" style="width:100%;max-width:260px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;">'
                + '<option value="epoch_ms"' + (tsValue === 'epoch_ms' ? ' selected' : '') + '>epoch_ms</option>'
                + '<option value="epoch_seconds"' + (tsValue === 'epoch_seconds' ? ' selected' : '') + '>epoch_seconds</option>'
                + '<option value="iso_8601"' + (tsValue === 'iso_8601' ? ' selected' : '') + '>iso_8601</option>'
                + '</select>'
                + (tsHelp ? '<div style="font-size:12px;color:#64748b;margin-top:4px;">' + htmlEscape(tsHelp) + '</div>' : ''))
              : '')
            + (buttons.length
              ? ('<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">'
                + buttons.map((btn) => {
                  const id = btn?.id || '';
                  const labelText = btn?.label || '';
                  const kind = btn?.kind || 'secondary';
                  const style = kind === 'danger'
                    ? 'background:#fff;border:1px solid #dc2626;color:#dc2626;'
                    : 'background:#fff;border:1px solid #cbd5e1;color:#0f172a;';
                  return '<button type="button" id="' + htmlEscape(id) + '" style="' + style + 'padding:6px 10px;border-radius:8px;">' + htmlEscape(labelText) + '</button>';
                }).join('')
                + '</div>')
              : '');
        }
        function renderRequestForm(prefix, options) {
          const verbs = Array.isArray(options?.verbs) && options.verbs.length
            ? options.verbs
            : ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
          const disableVerb = !!options?.disableVerb;
          const disableUrl = !!options?.disableUrl;
          const disableHeaders = !!options?.disableHeaders;
          const disableBody = !!options?.disableBody;
          const enableHttpAuthorization = !!options?.enableHttpAuthorization;
          const authProfileHint = options?.authProfileHint || "";
          const verbOptions = verbs
            .map((verb) => '<option value="' + htmlEscape(String(verb).toUpperCase()) + '">' + htmlEscape(String(verb).toUpperCase()) + '</option>')
            .join('');
          return ''
            + '<div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;">'
            + '<div style="min-width:110px;max-width:120px;flex:0 0 120px;">'
            + '<label for="' + prefix + '-verb" style="display:block;margin:8px 0 4px;">Method</label>'
            + '<select id="' + prefix + '-verb" ' + (disableVerb ? 'disabled ' : '')
            + 'style="width:100%;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;' + (disableVerb ? 'background:#f8fafc;' : '') + '">'
            + verbOptions
            + '</select>'
            + '</div>'
            + '<div style="min-width:220px;flex:1;">'
            + '<label for="' + prefix + '-url" style="display:block;margin:8px 0 4px;">URL</label>'
            + '<input id="' + prefix + '-url" type="text" placeholder="https://" ' + (disableUrl ? 'disabled ' : '')
            + 'style="width:100%;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;' + (disableUrl ? 'background:#f8fafc;' : '') + '" />'
            + '</div>'
            + '</div>'
            + renderHeaderList(prefix, {
              label: 'Headers',
              helpText: 'YAML-style: Header-Name: value per line',
              disabled: disableHeaders,
              rows: 4,
              placeholder: 'Header-Name: value',
            })
            + '<div style="display:flex;justify-content:space-between;align-items:center;margin:10px 0 4px;">'
            + '<label for="' + prefix + '-body">Request Body</label>'
            + '<a href="#" id="' + prefix + '-body-toggle" style="font-size:12px;text-decoration:underline;">hide</a>'
            + '</div>'
            + '<div id="' + prefix + '-body-wrap">'
            + '<textarea id="' + prefix + '-body" rows="8" placeholder="JSON or raw text" ' + (disableBody ? 'disabled ' : '')
            + 'style="width:100%;max-width:740px;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;' + (disableBody ? 'background:#f8fafc;' : '') + '"></textarea>'
            + '</div>'
            + (enableHttpAuthorization
              ? ('<div style="margin-top:12px;padding-top:10px;border-top:1px solid #e2e8f0;">'
                + '<label for="' + prefix + '-auth-type" style="display:block;margin:0 0 4px;">HTTP Authorization</label>'
                + '<select id="' + prefix + '-auth-type" style="width:100%;max-width:260px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;">'
                + '<option value="none">none</option>'
                + '<option value="static">static</option>'
                + '<option value="key_rotation">key_rotation</option>'
                + '</select>'
                + '<div id="' + prefix + '-auth-static-wrap" style="display:none;">'
                + '<label for="' + prefix + '-auth-header-name" style="display:block;margin:10px 0 4px;">Auth header name</label>'
                + '<input id="' + prefix + '-auth-header-name" type="text" placeholder="Authorization"'
                + ' style="width:100%;max-width:360px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
                + '<label for="' + prefix + '-auth-secret-ref" style="display:block;margin:10px 0 4px;">Auth key reference</label>'
                + '<input id="' + prefix + '-auth-secret-ref" type="text" placeholder="target_auth_key"'
                + ' style="width:100%;max-width:360px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
                + '<label for="' + prefix + '-auth-secret-value" style="display:block;margin:10px 0 4px;">Auth key value (password)</label>'
                + '<input id="' + prefix + '-auth-secret-value" type="password" placeholder="secret value"'
                + ' style="width:100%;max-width:420px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
                + '<div style="font-size:12px;color:#64748b;margin-top:4px;">Stored in KV and referenced as ${auth_key_ref} in YAML header value.</div>'
                + '</div>'
                + '<div id="' + prefix + '-auth-key-rotation-wrap" style="display:none;">'
                + '<label for="' + prefix + '-auth-profile" style="display:block;margin:10px 0 4px;">Key rotation profile</label>'
                + '<input id="' + prefix + '-auth-profile" type="text" placeholder="logging | target | jwt_inbound"'
                + ' style="width:100%;max-width:360px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
                + (authProfileHint ? '<div style="font-size:12px;color:#64748b;margin-top:4px;">' + htmlEscape(authProfileHint) + '</div>' : '')
                + '</div>'
                + '</div>')
              : '');
        }
        function setRequestAuthMode(prefix, type) {
          const mode = String(type || 'none');
          if (el(prefix + '-auth-type')) el(prefix + '-auth-type').value = mode;
          if (el(prefix + '-auth-static-wrap')) el(prefix + '-auth-static-wrap').style.display = mode === 'static' ? 'block' : 'none';
          if (el(prefix + '-auth-key-rotation-wrap')) el(prefix + '-auth-key-rotation-wrap').style.display = mode === 'key_rotation' ? 'block' : 'none';
        }
        function bindRequestFormToggles(prefix) {
          const headersToggle = el(prefix + '-headers-toggle');
          const headersWrap = el(prefix + '-headers-wrap');
          const headersHelp = el(prefix + '-headers-help');
          const bodyToggle = el(prefix + '-body-toggle');
          const bodyWrap = el(prefix + '-body-wrap');
          const setState = (toggleEl, wrapEl, helpEl, show) => {
            if (!toggleEl || !wrapEl) return;
            wrapEl.style.display = show ? 'block' : 'none';
            if (helpEl) helpEl.style.display = show ? 'block' : 'none';
            toggleEl.textContent = show ? 'hide' : 'show';
          };
          const bind = (toggleEl, wrapEl, helpEl) => {
            if (!toggleEl || !wrapEl) return;
            setState(toggleEl, wrapEl, helpEl, true);
            toggleEl.addEventListener('click', (evt) => {
              evt.preventDefault();
              const show = wrapEl.style.display === 'none';
              setState(toggleEl, wrapEl, helpEl, show);
            });
          };
          bind(headersToggle, headersWrap, headersHelp);
          bind(bodyToggle, bodyWrap, null);
          const authType = el(prefix + '-auth-type');
          if (authType) {
            authType.addEventListener('change', () => {
              setRequestAuthMode(prefix, authType.value || 'none');
            });
            setRequestAuthMode(prefix, authType.value || 'none');
          }
        }
        function bindHeaderListToggles(prefix) {
          const toggle = el(prefix + '-headers-toggle');
          const wrap = el(prefix + '-headers-wrap');
          const help = el(prefix + '-headers-help');
          if (!toggle || !wrap) return;
          const setState = (show) => {
            wrap.style.display = show ? 'block' : 'none';
            if (help) help.style.display = show ? 'block' : 'none';
            toggle.textContent = show ? 'hide' : 'show';
          };
          setState(true);
          toggle.addEventListener('click', (evt) => {
            evt.preventDefault();
            const show = wrap.style.display === 'none';
            setState(show);
          });
        }
        function bindSecretStorage(prefix, inputId) {
          const toggle = el(prefix + '-secret-toggle');
          const input = el(inputId || (prefix + '-secret'));
          if (!toggle || !input) return;
          toggle.addEventListener('click', (evt) => {
            evt.preventDefault();
            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            toggle.textContent = isHidden ? 'hide' : 'show';
          });
        }
        async function saveAuthProfileSecret(profile, inputId, outputId) {
          try {
            const value = String(el(inputId)?.value || '').trim();
            if (!value) throw new Error('Secret value is required.');
            await apiCall(ADMIN_ROOT + '/http-auth/' + encodeURIComponent(profile) + '/secret', 'PUT', { value });
            if (outputId) setOutput(outputId, 'Secret saved.');
            else showWarning('Secret saved.');
          } catch (e) {
            if (outputId) setOutput(outputId, String(e.message || e));
            else showWarning(String(e.message || e));
          }
        }
        async function deleteAuthProfileSecret(profile, outputId) {
          try {
            await apiCall(ADMIN_ROOT + '/http-auth/' + encodeURIComponent(profile) + '/secret', 'DELETE');
            if (outputId) setOutput(outputId, 'Secret deleted.');
            else showWarning('Secret deleted.');
          } catch (e) {
            if (outputId) setOutput(outputId, String(e.message || e));
            else showWarning(String(e.message || e));
          }
        }
        async function persistRequestAuthSecret(prefix) {
          const authType = String(el(prefix + '-auth-type')?.value || '').trim();
          if (authType !== 'static') return;
          const secretRef = String(el(prefix + '-auth-secret-ref')?.value || '').trim();
          const secretValue = String(el(prefix + '-auth-secret-value')?.value || '');
          if (!secretRef || !secretValue.trim()) return;
          await apiCall(ADMIN_ROOT + '/http-secrets/' + encodeURIComponent(secretRef), 'PUT', { value: secretValue });
        }
        function headersObjectToMultiline(obj) {
          if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return '';
          return Object.entries(obj)
            .map(([name, value]) => String(name) + ': ' + String(value ?? ''))
            .join('\n');
        }
        function headersArrayToObject(headers) {
          const out = {};
          (Array.isArray(headers) ? headers : []).forEach((item) => {
            const name = String(item?.name || '').trim();
            const value = String(item?.value || '').trim();
            if (name && value) out[name] = value;
          });
          return out;
        }
        function headersMultilineToObject(text) {
          const out = {};
          const lines = String(text || '').split('\n');
          for (const lineRaw of lines) {
            const line = lineRaw.trim();
            if (!line) continue;
            const idx = line.indexOf(':');
            if (idx === -1) {
              throw new Error('Headers must be in "Name: value" format.');
            }
            const name = line.slice(0, idx).trim();
            const value = line.slice(idx + 1).trim();
            if (!name) throw new Error('Header name is required.');
            out[name] = value;
          }
          return out;
        }
        function requestBodyFromText(text) {
          const raw = String(text ?? '').trim();
          if (!raw) return { type: 'none' };
          try {
            return { type: 'json', value: JSON.parse(raw) };
          } catch {
            return { type: 'raw', raw };
          }
        }
        function requestBodyToText(body) {
          if (!body || typeof body !== 'object') return '';
          if (body.type === 'none') return '';
          if (body.type === 'json') {
            try { return JSON.stringify(body.value ?? null, null, 2); } catch { return String(body.value ?? ''); }
          }
          if (body.type === 'urlencoded' && body.value && typeof body.value === 'object') {
            try { return new URLSearchParams(body.value).toString(); } catch { return String(body.value ?? ''); }
          }
          if (body.type === 'raw') return String(body.raw ?? '');
          if (body.raw != null) return String(body.raw);
          if (body.value != null) return typeof body.value === 'string' ? body.value : JSON.stringify(body.value, null, 2);
          return '';
        }
        function readRequestForm(prefix) {
          const headers = headersMultilineToObject(el(prefix + '-headers')?.value || '');
          const body = requestBodyFromText(el(prefix + '-body')?.value || '');
          const req = {
            method: String(el(prefix + '-verb')?.value || 'POST').toUpperCase(),
            url: String(el(prefix + '-url')?.value || '').trim(),
            headers,
          };
          req.body_type = body.type || 'none';
          if (body.type === 'json') req.body = body.value ?? {};
          else if (body.type === 'raw') req.body = body.raw ?? '';
          else if (body.type === 'urlencoded') req.body = body.value ?? {};
          else req.body = {};
          const authType = String(el(prefix + '-auth-type')?.value || '').trim();
          if (authType === 'static') {
            const headerName = String(el(prefix + '-auth-header-name')?.value || '').trim();
            const secretRef = String(el(prefix + '-auth-secret-ref')?.value || '').trim();
            const headers = {};
            if (headerName && secretRef) {
              headers[headerName] = '${' + secretRef + '}';
            }
            req.authorization = {
              type: 'static',
              static: {
                headers,
                secret_ref: secretRef || null,
              },
            };
          } else if (authType === 'key_rotation') {
            req.authorization = {
              type: 'key_rotation',
              key_rotation: {
                profile: String(el(prefix + '-auth-profile')?.value || '').trim(),
              },
            };
          }
          return req;
        }
        function setRequestForm(prefix, request) {
          const req = request && typeof request === 'object' ? request : {};
          const method = String(req.method || 'GET').toUpperCase();
          if (el(prefix + '-verb')) el(prefix + '-verb').value = method;
          if (el(prefix + '-url')) el(prefix + '-url').value = String(req.url || '');
          if (el(prefix + '-headers')) el(prefix + '-headers').value = headersObjectToMultiline(req.headers || {});
          const bodyForEditor =
            req.body_type
              ? ({
                  type: String(req.body_type || 'none').toLowerCase(),
                  value: req.body,
                  raw: typeof req.body === 'string' ? req.body : undefined,
                })
              : req.body;
          if (el(prefix + '-body')) el(prefix + '-body').value = requestBodyToText(bodyForEditor);
          const auth =
            req.authorization && typeof req.authorization === 'object'
              ? req.authorization
              : (req.http_authorization && typeof req.http_authorization === 'object' ? req.http_authorization : null);
          const authType = auth?.type === 'static' || auth?.type === 'key_rotation' ? auth.type : 'none';
          setRequestAuthMode(prefix, authType);
          if (el(prefix + '-auth-header-name')) {
            const staticHeaders = auth?.static?.headers && typeof auth.static.headers === 'object' ? auth.static.headers : {};
            const first = Object.entries(staticHeaders)[0] || [];
            el(prefix + '-auth-header-name').value = first[0] ? String(first[0]) : '';
          }
          if (el(prefix + '-auth-secret-ref')) {
            let secretRef = String(auth?.static?.secret_ref || '');
            if (!secretRef) {
              const staticHeaders = auth?.static?.headers && typeof auth.static.headers === 'object' ? auth.static.headers : {};
              const firstValue = Object.values(staticHeaders)[0];
              const matchCurly = String(firstValue || '').match(/{{\s*([a-zA-Z0-9_.-]+)\s*}}/);
              const matchDollar = String(firstValue || '').match(/\$\{\s*([a-zA-Z0-9_.-]+)\s*\}/);
              if (matchCurly) secretRef = matchCurly[1];
              else if (matchDollar) secretRef = matchDollar[1];
            }
            el(prefix + '-auth-secret-ref').value = secretRef;
          }
          if (el(prefix + '-auth-profile')) {
            el(prefix + '-auth-profile').value = String(auth?.key_rotation?.profile || '');
          }
        }
         function setHtml(id, html) {
           const node = el(id);
           if (!node) return;
           node.innerHTML = String(html || '');
         }
         function showWarning(message) {
           const node = el('admin-warning');
           if (!node) return;
           node.textContent = message || '';
           node.style.display = message ? 'block' : 'none';
         }
         function readKeyInput() {
           return (el('admin-key')?.value || '').trim();
         }
         function setConfigValidationError(message) {
           const field = el('config-yaml');
           const msg = el('config-validation-error');
           const text = String(message || '').trim();
           if (field) {
             field.style.borderColor = text ? '#dc2626' : '#cbd5e1';
             field.style.background = text ? '#fff5f5' : '#fff';
           }
           if (msg) {
             msg.style.display = text ? 'block' : 'none';
             msg.textContent = text;
           }
         }
        function setConfigSaveEnabled(enabled) {
          const btn = el('footer-save-config');
          if (!btn) return;
          btn.disabled = !enabled;
          btn.style.opacity = enabled ? '1' : '0.5';
          btn.style.cursor = enabled ? 'pointer' : 'not-allowed';
        }
        function markDirty(tabName) {
          if (!tabName) return;
          dirtyTabs.add(tabName);
        }
        function clearDirty(tabName) {
          if (!tabName) return;
          dirtyTabs.delete(tabName);
        }
        function confirmLeaveDirty(tabName) {
          if (!dirtyTabs.has(tabName)) return true;
          return window.confirm('Are you sure you want to leave this page before saving?');
        }
        function parseProxyNameFromYaml(yamlText) {
          const text = String(yamlText || '');
          const match = text.match(/^proxyName:\s*(.+)$/m);
          if (!match) return '';
          const raw = String(match[1] || '').trim();
          if (!raw || raw.toLowerCase() === 'null') return '';
          if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
            return raw.slice(1, -1);
          }
          return raw;
        }
        function applyProxyNameToYaml(yamlText, proxyName) {
          const name = String(proxyName || '').trim();
          const value = name ? '"' + name.replace(/"/g, '\\"') + '"' : 'null';
          const text = String(yamlText || '');
          if (text.match(/^proxyName:\s*/m)) {
            return text.replace(/^proxyName:\s*.*$/m, 'proxyName: ' + value);
          }
          const prefix = text.trim().length ? 'proxyName: ' + value + '\n' : 'proxyName: ' + value + '\n';
          return prefix + text;
        }
        async function fetchConfigJsonFromYaml() {
          const yamlText = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
          const res = await fetch(ADMIN_ROOT + '/config/validate', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'text/yaml' },
            body: yamlText,
          });
          if (res.status === 401) {
            handleUnauthorized();
            throw new Error('Unauthorized (401)');
          }
          const txt = await res.text();
          let parsed = null;
          try { parsed = JSON.parse(txt); } catch {}
          if (!res.ok || !parsed?.data?.config) {
            throw new Error('Failed to load config JSON');
          }
          return parsed.data.config;
        }
        function parseInboundHeaderFilteringFromYaml(yamlText) {
          const text = String(yamlText || '');
          const lines = text.split('\n');
          let inTransform = false;
          let inInbound = false;
          let inHeader = false;
          let inNames = false;
          let mode = '';
          const names = [];
          for (const line of lines) {
            if (/^\S/.test(line)) {
              inTransform = line.startsWith('transform:');
              inInbound = false;
              inHeader = false;
              inNames = false;
              continue;
            }
            if (inTransform && /^\s{2}\S/.test(line)) {
              inInbound = /^\s{2}inbound:\s*$/.test(line);
              inHeader = false;
              inNames = false;
              continue;
            }
            if (inInbound && /^\s{4}\S/.test(line)) {
              inHeader = /^\s{4}header_filtering:\s*$/.test(line);
              inNames = false;
              continue;
            }
            if (inHeader && /^\s{6}\S/.test(line)) {
              const modeMatch = line.match(/^\s{6}mode:\s*(\w+)\s*$/);
              if (modeMatch) {
                mode = modeMatch[1].toLowerCase();
                inNames = false;
                continue;
              }
              if (/^\s{6}names:\s*$/.test(line)) {
                inNames = true;
                continue;
              }
              inNames = false;
            }
            if (inHeader && inNames) {
              const itemMatch = line.match(/^\s{8}-\s*(.+)\s*$/);
              if (itemMatch) {
                names.push(itemMatch[1].trim());
              }
            }
          }
          if (!mode && names.length === 0) return null;
          return { mode, names };
        }
        function parseHeaderForwardingFromYaml(yamlText) {
          const text = String(yamlText || '');
          const lines = text.split('\n');
          let inHeader = false;
          let inNames = false;
          let mode = '';
          const names = [];
          for (const line of lines) {
            if (/^\S/.test(line)) {
              inHeader = line.startsWith('header_forwarding:');
              inNames = false;
              continue;
            }
            if (inHeader && /^\s{2}\S/.test(line)) {
              const modeMatch = line.match(/^\s{2}mode:\s*(\w+)\s*$/);
              if (modeMatch) {
                mode = modeMatch[1].toLowerCase();
                inNames = false;
                continue;
              }
              if (/^\s{2}names:\s*$/.test(line)) {
                inNames = true;
                continue;
              }
              inNames = false;
            }
            if (inHeader && inNames) {
              const itemMatch = line.match(/^\s{4}-\s*(.+)\s*$/);
              if (itemMatch) names.push(itemMatch[1].trim());
            }
          }
          if (!mode && names.length === 0) return null;
          return { mode, names };
        }
        function updateProxyHeader(proxyName) {
          const host = window.location.host || '';
          const name = String(proxyName || '').trim();
          const subtitle = host + (name ? ' (' + name + ')' : '');
          if (el('proxy-subtitle')) el('proxy-subtitle').textContent = subtitle;
          if (el('login-fqdn')) el('login-fqdn').textContent = host + (name ? ' (' + name + ')' : '');
        }
        function setJwtEnabled(enabled) {
          const on = !!enabled;
          if (el('jwt-enabled')) el('jwt-enabled').checked = on;
          if (el('jwt-fields')) el('jwt-fields').style.display = on ? 'block' : 'none';
        }
        function setJwtInboundEnabled(enabled) {
          const on = !!enabled;
          if (el('jwt-inbound-enabled')) el('jwt-inbound-enabled').checked = on;
          if (el('jwt-inbound-fields')) el('jwt-inbound-fields').style.display = on ? 'block' : 'none';
        }
        function setJwtOutboundEnabled(enabled) {
          const on = !!enabled;
          if (el('jwt-outbound-enabled')) el('jwt-outbound-enabled').checked = on;
          if (el('jwt-outbound-fields')) el('jwt-outbound-fields').style.display = on ? 'block' : 'none';
        }
        function updateJwtModeFields(modeValue) {
          const mode = String(modeValue || 'shared_secret');
          if (el('jwt-inbound-mode')) el('jwt-inbound-mode').value = mode;
          if (el('jwt-inbound-jwks-fields')) el('jwt-inbound-jwks-fields').style.display = mode === 'jwks' ? 'block' : 'none';
          if (el('jwt-inbound-shared-note')) el('jwt-inbound-shared-note').style.display = mode === 'shared_secret' ? 'block' : 'none';
        }
        function normalizeOptionalString(value) {
          const v = String(value || '').trim();
          return v ? v : null;
        }
        function normalizeOptionalInt(value) {
          const v = String(value == null ? '' : value).trim();
          if (!v) return null;
          const n = Number(v);
          if (!Number.isInteger(n) || n < 0) throw new Error('JWT numeric fields must be positive integers.');
          return n;
        }
        async function loadJwtConfig() {
          try {
            const config = await fetchConfigJsonFromYaml();
            const jwt = config?.jwt || {};
            const inbound = jwt.inbound || {};
            const outbound = jwt.outbound || {};
            const jwtInboundTs = config?.http_auth?.profiles?.jwt_inbound?.timestamp_format || 'epoch_ms';
            setJwtEnabled(jwt.enabled !== false);
            setJwtInboundEnabled(!!inbound.enabled);
            setJwtOutboundEnabled(!!outbound.enabled);
            updateJwtModeFields(inbound.mode || 'shared_secret');
            if (el('jwt-inbound-header')) el('jwt-inbound-header').value = String(inbound.header || 'Authorization');
            if (el('jwt-inbound-scheme')) el('jwt-inbound-scheme').value = String(inbound.scheme || 'Bearer');
            if (el('jwt-inbound-issuer')) el('jwt-inbound-issuer').value = inbound.issuer || '';
            if (el('jwt-inbound-audience')) el('jwt-inbound-audience').value = inbound.audience || '';
            setRequestForm('jwt-jwks', jwt.http_request || inbound.http_request || {});
            if (el('jwt-inbound-skew')) el('jwt-inbound-skew').value = inbound.clock_skew_seconds == null ? '' : String(inbound.clock_skew_seconds);
            if (el('jwt-outbound-header')) el('jwt-outbound-header').value = String(outbound.header || 'Authorization');
            if (el('jwt-outbound-scheme')) el('jwt-outbound-scheme').value = String(outbound.scheme || 'Bearer');
            if (el('jwt-outbound-issuer')) el('jwt-outbound-issuer').value = outbound.issuer || '';
            if (el('jwt-outbound-audience')) el('jwt-outbound-audience').value = outbound.audience || '';
            if (el('jwt-outbound-subject')) el('jwt-outbound-subject').value = outbound.subject || '';
            if (el('jwt-outbound-ttl')) el('jwt-outbound-ttl').value = outbound.ttl_seconds == null ? '' : String(outbound.ttl_seconds);
            if (el('jwt-inbound-ts-format')) el('jwt-inbound-ts-format').value = jwtInboundTs || 'epoch_ms';
          } catch {
            // no-op
          }
        }
        function openConfigTab() {
          document.querySelector('.tab-btn[data-tab="config"]')?.click();
        }
        function setOutboundMode() {}
         function extractApiErrorText(payload, fallback) {
           if (payload && typeof payload === 'object' && payload.error && typeof payload.error === 'object') {
             const code = payload.error.code ? String(payload.error.code) : 'ERROR';
             const message = payload.error.message ? String(payload.error.message) : String(fallback || 'Request failed');
             return code + ': ' + message;
           }
           return String(fallback || 'Request failed');
         }
         function formatConfigSummary(action, payload) {
           if (!payload || typeof payload !== 'object') {
             return action + '\\n\\n' + String(payload ?? '');
           }
           if (payload.ok === true && payload.data && typeof payload.data === 'object') {
             const lines = [action, ''];
             if (typeof payload.data.message === 'string' && payload.data.message) {
               lines.push('Message: ' + payload.data.message);
             }
             if (typeof payload.data.valid === 'boolean') {
               lines.push('Valid: ' + (payload.data.valid ? 'yes' : 'no'));
             }
             if (payload.data.matched_rule !== undefined) {
               lines.push('Matched rule: ' + (payload.data.matched_rule || 'none'));
             }
             if (payload.data.expression_source !== undefined) {
               lines.push('Expression source: ' + String(payload.data.expression_source || 'none'));
             }
             if (payload.data.fallback_behavior !== undefined) {
               lines.push('Fallback behavior: ' + String(payload.data.fallback_behavior));
             }
             if (payload.data.trace) {
               lines.push('Trace included: yes');
             }
             if (payload.data.output !== undefined) {
               lines.push('Output preview:');
               try {
                 lines.push(JSON.stringify(payload.data.output, null, 2));
               } catch {
                 lines.push(String(payload.data.output));
               }
             }
             return lines.join('\\n');
           }
           return action + '\\n\\n' + JSON.stringify(payload, null, 2);
         }
        function setCurrentKey(key, fromStorage) {
           currentKey = String(key || '').trim();
           const shell = el('admin-shell');
           const auth = el('admin-auth');
           if (shell) shell.style.display = currentKey ? 'block' : 'none';
           if (auth) auth.style.display = currentKey ? 'none' : 'block';
           if (!currentKey) {
             stopLiveLogStream();
             showWarning('');
              return;
            }
         }
        function handleUnauthorized() {
           stopLiveLogStream();
           currentKey = '';
           try { sessionStorage.removeItem(ADMIN_ACCESS_TOKEN_STORAGE); } catch {}
           if (el('admin-key')) el('admin-key').value = '';
           if (el('admin-shell')) el('admin-shell').style.display = 'none';
           if (el('admin-auth')) el('admin-auth').style.display = 'block';
           showWarning('Session logged out. Provide admin key again to login.');
         }
        function logoutExplicit() {
          stopLiveLogStream();
          currentKey = '';
          try { sessionStorage.removeItem(ADMIN_ACCESS_TOKEN_STORAGE); } catch {}
          if (el('admin-key')) el('admin-key').value = '';
          if (el('admin-shell')) el('admin-shell').style.display = 'none';
          if (el('admin-auth')) el('admin-auth').style.display = 'block';
          showWarning('');
        }
        async function apiCall(path, method, body, expectText) {
          if (!currentKey) {
            throw new Error('Login first.');
           }
           if (UI_DEBUG) {
             const safeBody = (path.includes('/config') && method !== 'GET') || typeof body === 'string' ? '(redacted)' : body;
             console.log('[api]', method, path, safeBody === undefined ? '' : safeBody);
           }
           const headers = { 'Authorization': 'Bearer ' + currentKey };
           if (body !== undefined && !expectText) headers['Content-Type'] = 'application/json';
           if (expectText) headers['Accept'] = 'text/plain';
           const res = await fetch(path, {
             method,
             headers,
             body: body === undefined ? undefined : (expectText ? body : JSON.stringify(body)),
           });
           if (res.status === 401) {
             handleUnauthorized();
             throw new Error('Unauthorized (401)');
           }
           const text = await res.text();
           if (expectText) return text;
           try { return JSON.parse(text); } catch { return text; }
         }
        function setLiveLogStatus(text, kind) {
          const node = el('live-log-status');
          if (!node) return;
          node.textContent = String(text || '');
          node.style.borderColor = '#ddd';
          node.style.background = '#fff';
          node.style.color = '#0f172a';
          if (kind === 'ok') {
            node.style.borderColor = '#bbf7d0';
            node.style.background = '#f0fdf4';
            node.style.color = '#14532d';
          } else if (kind === 'warn') {
            node.style.borderColor = '#fde68a';
            node.style.background = '#fefce8';
            node.style.color = '#854d0e';
          } else if (kind === 'error') {
            node.style.borderColor = '#fecaca';
            node.style.background = '#fef2f2';
            node.style.color = '#991b1b';
          }
        }
        function appendLiveLog(text) {
          const node = el('live-log-output');
          if (!node) return;
          const next = (node.textContent || '') + String(text || '') + '\n';
          node.textContent = next.length > LIVE_LOG_MAX_CHARS
            ? next.slice(next.length - LIVE_LOG_MAX_CHARS)
            : next;
          node.scrollTop = node.scrollHeight;
        }
        function clearLiveLogReconnectTimer() {
          if (liveLogReconnectTimer) {
            clearTimeout(liveLogReconnectTimer);
            liveLogReconnectTimer = null;
          }
        }
        function stopLiveLogStream() {
          liveLogShouldReconnect = false;
          clearLiveLogReconnectTimer();
          if (liveLogStreamAbortController) {
            try { liveLogStreamAbortController.abort(); } catch {}
            liveLogStreamAbortController = null;
          }
          setLiveLogStatus('Disconnected.', null);
        }
        function scheduleLiveLogReconnect(delayMs) {
          clearLiveLogReconnectTimer();
          if (!liveLogShouldReconnect || !currentKey || currentTabName !== 'live-log') return;
          liveLogReconnectTimer = setTimeout(() => {
            startLiveLogStream();
          }, Math.max(500, Number(delayMs || 1500)));
        }
        function parseSsePayload(block) {
          const lines = String(block || '').split('\n');
          let event = 'message';
          const dataLines = [];
          for (const line of lines) {
            if (!line || line.startsWith(':')) continue;
            if (line.startsWith('event:')) {
              event = line.slice(6).trim() || 'message';
              continue;
            }
            if (line.startsWith('data:')) {
              dataLines.push(line.slice(5).trimStart());
            }
          }
          return { event, data: dataLines.join('\n') };
        }
        async function startLiveLogStream() {
          if (!currentKey) {
            setLiveLogStatus('Login required.', 'warn');
            return;
          }
          if (currentTabName !== 'live-log') return;
          if (liveLogStreamAbortController) return;
          clearLiveLogReconnectTimer();
          liveLogShouldReconnect = true;
          const controller = new AbortController();
          liveLogStreamAbortController = controller;
          setLiveLogStatus('Connecting...', 'warn');
          try {
            const res = await fetch(ADMIN_ROOT + '/live-log/stream', {
              method: 'GET',
              headers: { 'Authorization': 'Bearer ' + currentKey, 'Accept': 'text/event-stream' },
              signal: controller.signal,
            });
            if (res.status === 401) {
              handleUnauthorized();
              setLiveLogStatus('Unauthorized. Login again.', 'error');
              return;
            }
            if (res.status === 409) {
              setLiveLogStatus('Logging is disabled. Enable logging first.', 'warn');
              return;
            }
            if (!res.ok || !res.body) {
              throw new Error('Stream failed (' + res.status + ')');
            }
            setLiveLogStatus('Connected. Streaming logs...', 'ok');
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              const blocks = buffer.split('\n\n');
              buffer = blocks.pop() || '';
              for (const block of blocks) {
                const parsed = parseSsePayload(block);
                if (!parsed.data) continue;
                let payload = parsed.data;
                try {
                  payload = JSON.parse(parsed.data);
                } catch {}
                if (parsed.event === 'trace') {
                  const traceText = (payload && typeof payload === 'object' && payload.text != null)
                    ? String(payload.text)
                    : String(parsed.data);
                  appendLiveLog(traceText);
                  continue;
                }
                if (parsed.event === 'connected') {
                  appendLiveLog('[connected] ' + (payload?.timestamp || new Date().toISOString()));
                  continue;
                }
                if (parsed.event === 'last_trace' && payload?.text) {
                  appendLiveLog('[last trace]\n' + String(payload.text));
                  continue;
                }
                appendLiveLog(typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2));
              }
            }
            if (liveLogShouldReconnect && currentTabName === 'live-log') {
              setLiveLogStatus('Disconnected. Reconnecting...', 'warn');
              liveLogStreamAbortController = null;
              scheduleLiveLogReconnect(1000);
              return;
            }
            setLiveLogStatus('Disconnected.', null);
          } catch (e) {
            if (controller.signal.aborted) {
              setLiveLogStatus('Disconnected.', null);
            } else {
              setLiveLogStatus('Stream error: ' + String(e.message || e), 'error');
              if (liveLogShouldReconnect && currentTabName === 'live-log') {
                scheduleLiveLogReconnect(2000);
              }
            }
          } finally {
            if (liveLogStreamAbortController === controller) {
              liveLogStreamAbortController = null;
            }
          }
        }
        async function loadLiveLogStatusAndMaybeConnect() {
          try {
            const payload = await apiCall(ADMIN_ROOT + '/debug', 'GET');
            const data = payload?.data || {};
            const enabled = !!data.enabled;
            if (!enabled) {
              stopLiveLogStream();
              setLiveLogStatus('Logging is disabled. Enable it on the Logging page to stream logs.', 'warn');
              return;
            }
            setLiveLogStatus('Logging is enabled. Connecting...', 'ok');
            if (currentTabName === 'live-log') {
              startLiveLogStream();
            }
          } catch (e) {
            setLiveLogStatus('Unable to load logging status: ' + String(e.message || e), 'error');
          }
        }
        function attachTabs() {
          const btns = document.querySelectorAll('.tab-btn');
          const panels = document.querySelectorAll('.tab-panel');
          function setActiveTab(name) {
            if (name === currentTabName) return;
            if (!confirmLeaveDirty(currentTabName)) return;
            if (currentTabName === 'live-log' && name !== 'live-log') {
              stopLiveLogStream();
            }
            panels.forEach((panel) => {
              panel.style.display = panel.id === 'tab-' + name ? 'block' : 'none';
            });
             btns.forEach((btn) => {
               const active = btn.getAttribute('data-tab') === name;
               btn.style.background = active ? '#111827' : '#fff';
               btn.style.color = active ? '#fff' : '#0f172a';
               btn.style.borderColor = active ? '#111827' : '#cbd5e1';
               btn.style.fontWeight = active ? '700' : '500';
             });
            if (name === 'debug') {
              if (el('logging-secret-template') && !el('logging-secret')) {
                setHtml('logging-secret-template', renderSecretStorage('logging', {
                  label: 'Logging auth secret',
                  placeholder: 'set logging auth secret',
                  inputId: 'logging-secret',
                  timestampFormatId: 'logging-ts-format',
                  timestampFormatLabel: 'Timestamp format',
                  timestampFormatValue: 'epoch_ms',
                  buttons: [{ id: 'logging-secret-delete-btn', label: 'Delete secret', kind: 'danger' }],
                }));
                bindSecretStorage('logging', 'logging-secret');
                bindOnce('logging-secret-delete-btn', loggingSecretDelete);
              }
              debugLoadTrace();
              loadLoggingStatus();
            }
            if (name === 'live-log') {
              loadLiveLogStatusAndMaybeConnect();
            }
            if (name === 'outbound-auth') {
              keyRotationLoad();
            }
            if (name === 'outbound-transform') {
              transformConfigLoad();
              headersList();
              if (el('headers-input-wrap')) {
                setHtml('headers-input-wrap', renderHeaderList('headers-input', {
                  label: 'Headers',
                  helpText: 'YAML-style: Header-Name: value per line',
                  disabled: false,
                  rows: 5,
                  placeholder: 'Header-Name: value',
                  value: '',
                }));
                bindHeaderListToggles('headers-input');
              }
            }
            if (name === 'admin-auth') {
              keysRefresh();
            }
            if (name === 'inbound-auth') {
              keyRotationLoad();
              keysRefresh();
              if (el('jwt-inbound-secret-template') && !el('jwt-inbound-secret')) {
                setHtml('jwt-inbound-secret-template', renderSecretStorage('jwt-inbound', {
                  label: 'JWT inbound auth secret',
                  placeholder: 'set JWT auth secret',
                  inputId: 'jwt-inbound-secret',
                  timestampFormatId: 'jwt-inbound-ts-format',
                  timestampFormatLabel: 'Timestamp format',
                  timestampFormatValue: 'epoch_ms',
                  buttons: [
                    { id: 'jwt-inbound-save-btn', label: 'Save/Update secret' },
                    { id: 'jwt-inbound-delete-btn', label: 'Delete secret', kind: 'danger' },
                  ],
                }));
                bindSecretStorage('jwt-inbound', 'jwt-inbound-secret');
                bindOnce('jwt-inbound-save-btn', () => saveAuthProfileSecret('jwt_inbound', 'jwt-inbound-secret', 'keys-output'));
                bindOnce('jwt-inbound-delete-btn', () => deleteAuthProfileSecret('jwt_inbound', 'keys-output'));
              }
            }
            if (name === 'inbound-transform') transformConfigLoad();
            if (name === 'sandbox') sandboxInit();
            currentTabName = name;
          }
           btns.forEach((btn) => {
             btn.style.padding = '8px 10px';
             btn.style.border = '1px solid #cbd5e1';
             btn.style.borderRadius = '8px';
             btn.style.background = '#fff';
             btn.style.textAlign = 'left';
             btn.style.cursor = 'pointer';
             if (btn.classList.contains('tab-child')) {
               btn.style.marginLeft = '14px';
             }
             btn.addEventListener('click', () => {
               const name = btn.getAttribute('data-tab');
               setActiveTab(name);
             });
           });
          setActiveTab('overview');
        }
        function formatOverviewStatus(version, debug, headers, targetHost, proxyName) {
          const versionText = version?.data?.version || 'unknown';
          const buildTimestamp = version?.data?.build_timestamp || '';
          const debugData = debug?.data || {};
          const debugEnabled = !!debugData.enabled;
          const enrichedHeaders = Array.isArray(headers?.enriched_headers)
            ? headers.enriched_headers
            : (Array.isArray(headers?.data?.enriched_headers) ? headers.data.enriched_headers : []);
          return '<div><b>Proxy Name:</b> ' + (proxyName || 'n/a') + '</div>'
            + '<div><b>Debug Enabled:</b> ' + (debugEnabled ? 'yes' : 'no') + '</div>'
            + '<div><b>Target URL:</b> ' + (targetHost || 'n/a') + '</div>'
            + '<div><b>Enrichments:</b> ' + (enrichedHeaders.length ? enrichedHeaders.join(', ') : 'n/a') + '</div>';
        }
         async function refreshOverview() {
           try {
             const [version, debug, headers, yamlText] = await Promise.all([
               apiCall(ADMIN_ROOT + '/version', 'GET'),
               apiCall(ADMIN_ROOT + '/debug', 'GET'),
               apiCall(ADMIN_ROOT + '/headers', 'GET'),
               apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true),
             ]);
            let targetHost = '';
            let proxyName = '';
            try {
              const res = await fetch(ADMIN_ROOT + '/config/validate', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'text/yaml' },
                body: yamlText,
              });
              const txt = await res.text();
              const parsed = JSON.parse(txt);
              if (res.ok) {
                targetHost = parsed?.data?.config?.targetHost || '';
                proxyName = parsed?.data?.config?.proxyName || '';
              }
            } catch {}
            setHtml('overview-output', formatOverviewStatus(version, debug, headers, targetHost, proxyName));
          } catch (e) {
            setOutput('overview-output', String(e.message || e));
          }
        }
         async function debugEnable() {
           try {
             const ttl = Number(el('logging-ttl-seconds')?.value || 0);
             if (!Number.isInteger(ttl) || ttl < 1) {
               throw new Error('Logging TTL must be a positive integer.');
             }
             await apiCall(ADMIN_ROOT + '/debug', 'PUT', { enabled: true, ttl_seconds: ttl });
             await loadLoggingStatus();
           }
           catch (e) { showWarning(String(e.message || e)); }
         }
         async function debugDisable() {
           try {
             await apiCall(ADMIN_ROOT + '/debug', 'DELETE');
             await loadLoggingStatus();
           }
           catch (e) { showWarning(String(e.message || e)); }
         }
         async function debugLoadTrace() {
           try { setOutput('debug-output', await apiCall(ADMIN_ROOT + '/debug/last', 'GET', undefined, true)); }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
        async function loggingSave() {
          try {
            const enabled = !!el('logging-config-enabled')?.checked;
            const config = await fetchConfigJsonFromYaml();
            if (!config.debug) config.debug = {};
            if (enabled) {
              const req = readRequestForm('logging-req');
              await persistRequestAuthSecret('logging-req');
              config.debug.loggingEndpoint = { http_request: req };
            } else {
              config.debug.loggingEndpoint = { http_request: null };
            }
            if (!config.http_auth) config.http_auth = {};
            if (!config.http_auth.profiles) config.http_auth.profiles = {};
            if (!config.http_auth.profiles.logging) config.http_auth.profiles.logging = { headers: {} };
            if (el('logging-ts-format')) {
              config.http_auth.profiles.logging.timestamp_format = el('logging-ts-format')?.value || 'epoch_ms';
            }
            const cfgRes = await fetch(ADMIN_ROOT + '/config', {
              method: 'PUT',
              headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'application/json' },
              body: JSON.stringify(config),
            });
            if (cfgRes.status === 401) {
              handleUnauthorized();
              throw new Error('Unauthorized (401)');
            }
            if (!cfgRes.ok) {
              const text = await cfgRes.text();
              throw new Error(text || 'Failed to save logging config');
            }
            const secretValue = el('logging-secret')?.value || '';
            if (secretValue.trim()) {
              await apiCall(ADMIN_ROOT + '/debug/loggingSecret', 'PUT', { value: secretValue });
            }
            await loadLoggingStatus();
            clearDirty('debug');
          } catch (e) {
            showWarning(String(e.message || e));
          }
        }
         async function loggingSecretDelete() {
           try {
             await apiCall(ADMIN_ROOT + '/debug/loggingSecret', 'DELETE');
             await loadLoggingStatus();
           }
           catch (e) { showWarning(String(e.message || e)); }
         }
        async function loadLoggingStatus() {
          try {
            const [debugStatus, secretStatus, yamlText] = await Promise.all([
              apiCall(ADMIN_ROOT + '/debug', 'GET'),
              apiCall(ADMIN_ROOT + '/debug/loggingSecret', 'GET'),
              apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true),
            ]);
            let endpointRequest = null;
            let loggingTsFormat = 'epoch_ms';
            try {
              const res = await fetch(ADMIN_ROOT + '/config/validate', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'text/yaml' },
                body: yamlText,
              });
               const txt = await res.text();
               let parsed = null;
               try { parsed = JSON.parse(txt); } catch {}
              if (res.ok && parsed?.data?.config?.debug?.loggingEndpoint) {
                const cfg = parsed.data.config.debug.loggingEndpoint;
                endpointRequest = cfg.http_request || null;
              }
              if (res.ok && parsed?.data?.config?.http_auth?.profiles?.logging?.timestamp_format) {
                loggingTsFormat = parsed.data.config.http_auth.profiles.logging.timestamp_format || 'epoch_ms';
              }
            } catch {}
            setRequestForm('logging-req', endpointRequest || {});
            if (el('logging-ts-format')) el('logging-ts-format').value = loggingTsFormat || 'epoch_ms';
            const d = debugStatus?.data || {};
            const enabledText = d.enabled ? 'enabled' : 'disabled';
            if (el('logging-status')) {
              const html = d.enabled
                ? '<div style="background:#fef9c3;border:1px solid #fde68a;color:#92400e;padding:8px 10px;border-radius:8px;margin-bottom:6px;">Logging is enabled.</div>'
                  + '<b>Logging:</b> <b>enabled</b> | <a href="#" id="logging-disable-link">disable</a>'
                : '<b>Logging:</b> <a href="#" id="logging-enable-link">enable</a> | <b>disabled</b>';
              setHtml('logging-status', html);
            }
            const ttlRemaining = Number.isFinite(Number(d.ttl_remaining_seconds)) ? Number(d.ttl_remaining_seconds) : null;
            if (el('logging-ttl-remaining-2')) {
              el('logging-ttl-remaining-2').textContent = ttlRemaining === null ? 'n/a' : String(ttlRemaining);
            }
            if (el('logging-ttl-seconds') && Number(d.max_ttl_seconds || 0) > 0 && !el('logging-ttl-seconds').value) {
              el('logging-ttl-seconds').value = String(Number(d.max_ttl_seconds));
            }
            const configEnabled = !!(endpointRequest && endpointRequest.url);
            if (el('logging-config-enabled')) el('logging-config-enabled').checked = configEnabled;
            if (el('logging-config-fields')) el('logging-config-fields').style.display = configEnabled ? 'block' : 'none';
            if (el('logging-secret-wrap')) el('logging-secret-wrap').style.display = configEnabled ? 'block' : 'none';
            if (currentTabName === 'live-log') {
              if (d.enabled) {
                setLiveLogStatus('Logging is enabled. Connecting...', 'ok');
                startLiveLogStream();
              } else {
                stopLiveLogStream();
                setLiveLogStatus('Logging is disabled. Enable it on the Logging page to stream logs.', 'warn');
              }
            }
          } catch (e) {
            showWarning(String(e.message || e));
          }
        }
        async function configLoad() {
          try {
            const text = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
            if (UI_DEBUG) {
              console.log('[config yaml]', text);
            }
            if (el('config-yaml')) el('config-yaml').value = text;
            if (el('proxy-name')) el('proxy-name').value = parseProxyNameFromYaml(text);
            updateProxyHeader(el('proxy-name')?.value || '');
            setConfigValidationError('');
            setConfigSaveEnabled(true);
            setOutput('config-output', 'Config reloaded from proxy.');
            clearDirty('config');
          } catch (e) {
             setOutput('config-output', String(e.message || e));
             setConfigSaveEnabled(false);
          }
        }
        async function configValidate(showOutput) {
          const yaml = applyProxyNameToYaml(el('config-yaml')?.value || '', el('proxy-name')?.value || '');
          if (el('config-yaml')) el('config-yaml').value = yaml;
          try {
            const res = await fetch(ADMIN_ROOT + '/config/validate', {
              method: 'POST',
              headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'text/yaml' },
              body: yaml,
             });
             if (res.status === 401) {
               handleUnauthorized();
               throw new Error('Unauthorized (401)');
             }
             const text = await res.text();
             let payload = null;
             try {
               payload = JSON.parse(text);
             } catch {
               payload = null;
             }
             if (!res.ok) {
               const errText = extractApiErrorText(payload, text || 'Config validation failed');
               setConfigValidationError(errText);
               setConfigSaveEnabled(false);
               if (showOutput) setOutput('config-output', 'Validation failed\\n\\n' + errText);
               return false;
             }
             setConfigValidationError('');
             setConfigSaveEnabled(true);
             if (showOutput) setOutput('config-output', formatConfigSummary('Validation successful', payload));
             return true;
           } catch (e) {
             const errText = String(e.message || e);
             setConfigValidationError(errText);
             setConfigSaveEnabled(false);
             if (showOutput) setOutput('config-output', 'Validation failed\\n\\n' + errText);
             return false;
           }
         }
        async function configSave() {
          const yaml = applyProxyNameToYaml(el('config-yaml')?.value || '', el('proxy-name')?.value || '');
          if (el('config-yaml')) el('config-yaml').value = yaml;
          const valid = await configValidate(false);
          if (!valid) {
            setOutput('config-output', 'Save blocked: fix config validation errors first.');
            return;
          }
          try {
            if (UI_DEBUG) {
              const prev = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
              if (typeof prev === 'string') {
                console.log('[config diff]', diffText(prev, yaml));
              }
            }
            const res = await fetch(ADMIN_ROOT + '/config', {
              method: 'PUT',
              headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'text/yaml' },
              body: yaml,
            });
             if (res.status === 401) {
               handleUnauthorized();
               throw new Error('Unauthorized (401)');
             }
             const text = await res.text();
             try {
               setOutput('config-output', formatConfigSummary('Config saved', JSON.parse(text)));
             } catch {
               setOutput('config-output', text);
             }
             clearDirty('config');
           } catch (e) {
             setOutput('config-output', String(e.message || e));
           }
         }
         async function configTestRule() {
           const raw = el('config-test-rule-input')?.value || '';
           let parsed;
           try {
             parsed = raw ? JSON.parse(raw) : {};
           } catch {
             setOutput('config-output', 'Test rule input must be valid JSON.');
             return;
           }
           try {
             const result = await apiCall(ADMIN_ROOT + '/config/test-rule', 'POST', parsed);
             setOutput('config-output', formatConfigSummary('Rule test result', result));
           } catch (e) {
             setOutput('config-output', String(e.message || e));
           }
         }
         function normalizeNullableIntegerInput(raw) {
           const v = String(raw == null ? '' : raw).trim();
           if (!v || v.toLowerCase() === 'null') return null;
           const n = Number(v);
           if (!Number.isInteger(n) || n < 1) throw new Error('Expiry fields must be null or positive integers.');
           return n;
         }
        async function keyRotationLoad() {
          try {
            const payload = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'GET');
            let targetTsFormat = 'epoch_ms';
            try {
              const config = await fetchConfigJsonFromYaml();
              targetTsFormat = config?.http_auth?.profiles?.target?.timestamp_format || 'epoch_ms';
            } catch {}
            const d = payload?.data || {};
            if (el('target-auth-ts-format')) el('target-auth-ts-format').value = targetTsFormat || 'epoch_ms';
             setOutboundAuthEnabled(!!d.enabled);
             if (el('kr-enabled')) el('kr-enabled').checked = !!d.enabled;
             if (el('kr-strategy')) el('kr-strategy').value = d.strategy || 'json_ttl';
             if (el('kr-request-form')) setRequestForm('kr', d.request || {});
             if (el('kr-key-path')) el('kr-key-path').value = String(d.key_path || '');
             if (el('kr-ttl-path')) el('kr-ttl-path').value = d.ttl_path == null ? '' : String(d.ttl_path);
             if (el('kr-ttl-unit')) el('kr-ttl-unit').value = d.ttl_unit || 'seconds';
             if (el('kr-expires-at-path')) el('kr-expires-at-path').value = d.expires_at_path == null ? '' : String(d.expires_at_path);
             if (el('kr-refresh-skew')) el('kr-refresh-skew').value = String(Number(d.refresh_skew_seconds || 0));
             if (el('kr-retry-on-401')) el('kr-retry-on-401').checked = !!d.retry_once_on_401;
            if (el('kr-proxy-expiry')) el('kr-proxy-expiry').value = d.proxy_expiry_seconds == null ? '' : String(d.proxy_expiry_seconds);
            if (el('kr-issuer-expiry')) el('kr-issuer-expiry').value = d.issuer_expiry_seconds == null ? '' : String(d.issuer_expiry_seconds);
            if (el('kr-admin-expiry')) el('kr-admin-expiry').value = d.admin_expiry_seconds == null ? '' : String(d.admin_expiry_seconds);
            if (el('kr-output')) el('kr-output').textContent = '';
            clearDirty('outbound-auth');
            await loadJwtConfig();
          } catch (e) {
            setOutput('kr-output', String(e.message || e));
          }
        }
        async function keyRotationSave() {
          try {
            const outboundAuthEnabled = !!el('outbound-auth-enabled')?.checked;
            if (el('kr-enabled')) el('kr-enabled').checked = outboundAuthEnabled;
             const req = readRequestForm('kr');
             await persistRequestAuthSecret('kr');
             const payload = {
               enabled: outboundAuthEnabled,
               strategy: (el('kr-strategy')?.value || 'json_ttl'),
               request: req,
               key_path: el('kr-key-path')?.value || '',
               ttl_path: el('kr-ttl-path')?.value || null,
               ttl_unit: el('kr-ttl-unit')?.value || 'seconds',
               expires_at_path: el('kr-expires-at-path')?.value || null,
               refresh_skew_seconds: Number(el('kr-refresh-skew')?.value || 0),
               retry_once_on_401: !!el('kr-retry-on-401')?.checked,
             };
            const out = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'PUT', payload);
            try {
              const config = await fetchConfigJsonFromYaml();
              if (!config.http_auth) config.http_auth = {};
              if (!config.http_auth.profiles) config.http_auth.profiles = {};
              if (!config.http_auth.profiles.target) config.http_auth.profiles.target = { headers: {} };
              if (el('target-auth-ts-format')) {
                config.http_auth.profiles.target.timestamp_format = el('target-auth-ts-format')?.value || 'epoch_ms';
              }
              await fetch(ADMIN_ROOT + '/config', {
                method: 'PUT',
                headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
              });
            } catch {}
            setOutput('kr-output', out);
            clearDirty('outbound-auth');
          } catch (e) {
            setOutput('kr-output', String(e.message || e));
          }
        }
        async function inboundAuthSave() {
          try {
            const config = await fetchConfigJsonFromYaml();
            const jwtEnabled = !!el('jwt-enabled')?.checked;
            const inboundEnabled = !!el('jwt-inbound-enabled')?.checked;
            const outboundEnabled = !!el('jwt-outbound-enabled')?.checked;
            const inboundMode = el('jwt-inbound-mode')?.value || 'shared_secret';
            const jwksRequest = readRequestForm('jwt-jwks');
            if (inboundMode === 'jwks') {
              await persistRequestAuthSecret('jwt-jwks');
            }
            const jwtConfig = {
              enabled: jwtEnabled,
              inbound: {
                enabled: inboundEnabled,
                mode: inboundMode,
                header: normalizeOptionalString(el('jwt-inbound-header')?.value) || 'Authorization',
                scheme: normalizeOptionalString(el('jwt-inbound-scheme')?.value),
                issuer: normalizeOptionalString(el('jwt-inbound-issuer')?.value),
                audience: normalizeOptionalString(el('jwt-inbound-audience')?.value),
                http_request: inboundMode === 'jwks' ? jwksRequest : null,
                clock_skew_seconds: normalizeOptionalInt(el('jwt-inbound-skew')?.value),
              },
              outbound: {
                enabled: outboundEnabled,
                header: normalizeOptionalString(el('jwt-outbound-header')?.value) || 'Authorization',
                scheme: normalizeOptionalString(el('jwt-outbound-scheme')?.value),
                issuer: normalizeOptionalString(el('jwt-outbound-issuer')?.value),
                audience: normalizeOptionalString(el('jwt-outbound-audience')?.value),
                subject: normalizeOptionalString(el('jwt-outbound-subject')?.value),
                ttl_seconds: normalizeOptionalInt(el('jwt-outbound-ttl')?.value),
              },
              http_request: inboundMode === 'jwks' ? jwksRequest : null,
              authorization: inboundMode === 'jwks' ? (jwksRequest.authorization || null) : null,
            };
            config.jwt = jwtConfig;
            if (!config.http_auth) config.http_auth = {};
            if (!config.http_auth.profiles) config.http_auth.profiles = {};
            if (!config.http_auth.profiles.jwt_inbound) config.http_auth.profiles.jwt_inbound = { headers: {} };
            if (el('jwt-inbound-ts-format')) {
              config.http_auth.profiles.jwt_inbound.timestamp_format = el('jwt-inbound-ts-format')?.value || 'epoch_ms';
            }
            const cfgRes = await fetch(ADMIN_ROOT + '/config', {
              method: 'PUT',
              headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'application/json' },
              body: JSON.stringify(config),
            });
            if (cfgRes.status === 401) {
              handleUnauthorized();
              throw new Error('Unauthorized (401)');
            }
            if (!cfgRes.ok) {
              const text = await cfgRes.text();
              throw new Error(text || 'Failed to save JWT settings');
            }
            const current = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'GET');
            const d = current?.data || {};
            const payload = {
              enabled: !!d.enabled,
              strategy: d.strategy || 'json_ttl',
              request: d.request || {},
              key_path: d.key_path || '',
              ttl_path: d.ttl_path ?? null,
              ttl_unit: d.ttl_unit || 'seconds',
              expires_at_path: d.expires_at_path ?? null,
              refresh_skew_seconds: Number(d.refresh_skew_seconds || 0),
              retry_once_on_401: !!d.retry_once_on_401,
              proxy_expiry_seconds: normalizeNullableIntegerInput(el('kr-proxy-expiry')?.value),
              issuer_expiry_seconds: normalizeNullableIntegerInput(el('kr-issuer-expiry')?.value),
              admin_expiry_seconds: d.admin_expiry_seconds ?? null,
              static_header_key: d.static_header_key ?? null,
              static_header_value: d.static_header_value ?? null,
            };
            const out = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'PUT', payload);
            setOutput('keys-output', out);
            await keysRefresh();
            clearDirty('inbound-auth');
          } catch (e) {
            setOutput('keys-output', String(e.message || e));
          }
        }
        function diffText(prevText, nextText) {
          const a = String(prevText || '').split('\n');
          const b = String(nextText || '').split('\n');
          const max = Math.max(a.length, b.length);
          const lines = [];
          for (let i = 0; i < max; i += 1) {
            const left = a[i];
            const right = b[i];
            if (left === right) continue;
            if (left !== undefined) lines.push('- ' + left);
            if (right !== undefined) lines.push('+ ' + right);
          }
          return lines.join('\n') || '(no changes)';
        }
        async function adminAuthSave() {
          try {
            const current = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'GET');
            const d = current?.data || {};
            const payload = {
              enabled: !!d.enabled,
              strategy: d.strategy || 'json_ttl',
              request: d.request || {},
              key_path: d.key_path || '',
              ttl_path: d.ttl_path ?? null,
              ttl_unit: d.ttl_unit || 'seconds',
              expires_at_path: d.expires_at_path ?? null,
              refresh_skew_seconds: Number(d.refresh_skew_seconds || 0),
              retry_once_on_401: !!d.retry_once_on_401,
              proxy_expiry_seconds: d.proxy_expiry_seconds ?? null,
              issuer_expiry_seconds: d.issuer_expiry_seconds ?? null,
              admin_expiry_seconds: normalizeNullableIntegerInput(el('kr-admin-expiry')?.value),
              static_header_key: d.static_header_key ?? null,
              static_header_value: d.static_header_value ?? null,
            };
            const out = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'PUT', payload);
            setOutput('admin-keys-output', out);
            await keysRefresh();
            clearDirty('admin-auth');
          } catch (e) {
            setOutput('admin-keys-output', String(e.message || e));
          }
        }
        function setOutboundAuthEnabled(enabled) {
          const on = !!enabled;
          if (el('outbound-auth-enabled')) el('outbound-auth-enabled').checked = on;
          if (el('outbound-auth-fields')) el('outbound-auth-fields').style.display = on ? 'block' : 'none';
        }
        function updateInboundHeaderFilteringHelp(modeValue) {
          const mode = String(modeValue || 'blacklist');
          const node = el('inbound-header-filtering-help');
          if (!node) return;
          node.textContent = mode === 'whitelist'
            ? 'Headers not included in this list will be ignored.'
            : 'These headers will not be forwarded in the request.';
        }
        function emptyOutboundRule() {
          return { name: '', method: [], headers: [], expr: '' };
        }
        function emptyInboundRule() {
          return { name: '', status: [], headers: [], expr: '' };
        }
        function normalizeRuleHeadersForUi(rule) {
          const headers = [];
          if (Array.isArray(rule?.headers)) {
            rule.headers.forEach((item) => {
              const name = String(item?.name || '').trim();
              const value = String(item?.value || '').trim();
              if (name && value) headers.push({ name, value });
            });
          } else if (rule?.headerMatch && typeof rule.headerMatch === 'object') {
            for (const [name, value] of Object.entries(rule.headerMatch || {})) {
              const n = String(name || '').trim();
              const v = String(value || '').trim();
              if (n && v) headers.push({ name: n, value: v });
            }
          }
          return headers;
        }
        function normalizeRuleForUi(rule) {
          const headers = normalizeRuleHeadersForUi(rule || {});
          return { ...rule, headers };
        }
        function validateHttpMethodList(raw) {
          const list = parseCsvList(raw);
          if (!list.length) return { ok: false, message: 'At least one HTTP method is required.' };
          for (const item of list) {
            if (!/^[A-Za-z]+$/.test(item)) return { ok: false, message: 'Methods must be letters only (comma-separated).' };
          }
          return { ok: true, value: list.map((m) => m.toUpperCase()) };
        }
        function validateStatusList(raw) {
          const list = parseCsvList(raw);
          if (!list.length) return { ok: false, message: 'At least one status code or class is required.' };
          for (const item of list) {
            if (/^\d+$/.test(item)) {
              const n = Number(item);
              if (!Number.isInteger(n) || n < 100 || n > 999) return { ok: false, message: 'HTTP codes must be between 100 and 999.' };
              continue;
            }
            if (!/^[1-5]xx$/i.test(item)) return { ok: false, message: 'Classes must be like 2xx, 4xx, 5xx.' };
          }
          return { ok: true, value: list };
        }
        function renderTransformRules(kind) {
          const listId = kind === 'outbound' ? 'outbound-rules-list' : 'inbound-rules-list';
          const rules = kind === 'outbound' ? outboundRuleDrafts : inboundRuleDrafts;
          const node = el(listId);
          if (!node) return;
          if (!rules.length) {
             node.innerHTML = '<div style="color:#64748b;">(no rules)</div>';
             return;
           }
          node.innerHTML = rules.map((rule, i) => {
            const method = Array.isArray(rule.method) ? rule.method.join(', ') : '';
            const status = Array.isArray(rule.status) ? rule.status.join(', ') : '';
            const headers = normalizeRuleHeadersForUi(rule);
            const methodEnabled = Array.isArray(rule.method) && rule.method.length > 0;
            const statusEnabled = Array.isArray(rule.status) && rule.status.length > 0;
            const headersEnabled = headers.length > 0;
            const methodTarget = 'rule-' + kind + '-' + i + '-method';
            const statusTarget = 'rule-' + kind + '-' + i + '-status';
            const headersTarget = 'rule-' + kind + '-' + i + '-headers';
            const headerValue = headersObjectToMultiline(headersArrayToObject(headers));
            return '<div style="border:1px solid #e2e8f0;border-radius:8px;padding:10px;">'
              + '<label style="display:block;margin:0 0 4px;">Name</label>'
              + '<input data-kind="' + kind + '" data-field="name" data-index="' + i + '" value="' + htmlEscape(rule.name || '') + '" style="width:100%;max-width:460px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
              + '<label style="display:flex;gap:8px;align-items:center;margin:10px 0 6px;">'
              + '<input type="checkbox" class="rule-match-toggle" data-kind="' + kind + '" data-index="' + i + '" data-target="' + methodTarget + '"' + (methodEnabled ? ' checked' : '') + ' />'
              + '<span>Match On HTTP Method</span>'
              + '</label>'
              + '<div id="' + methodTarget + '" style="display:' + (methodEnabled ? 'block' : 'none') + ';">'
              + '<label style="display:block;margin:6px 0 4px;">Method list (comma-separated)</label>'
              + '<input data-kind="' + kind + '" data-field="method" data-index="' + i + '" value="' + htmlEscape(method) + '" style="width:100%;max-width:460px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
              + '<div style="font-size:12px;color:#64748b;margin-top:4px;">e.g. GET, POST, DEL</div>'
              + '<div data-kind="' + kind + '" data-error="method" data-index="' + i + '" style="display:none;font-size:12px;color:#b91c1c;margin-top:4px;"></div>'
              + '</div>'
              + (kind === 'inbound'
                ? ('<label style="display:flex;gap:8px;align-items:center;margin:10px 0 6px;">'
                  + '<input type="checkbox" class="rule-match-toggle" data-kind="' + kind + '" data-index="' + i + '" data-target="' + statusTarget + '"' + (statusEnabled ? ' checked' : '') + ' />'
                  + '<span>Match On HTTP Codes</span>'
                  + '</label>'
                  + '<div id="' + statusTarget + '" style="display:' + (statusEnabled ? 'block' : 'none') + ';">'
                  + '<label style="display:block;margin:6px 0 4px;">Response code list (comma-separated)</label>'
                  + '<input data-kind="' + kind + '" data-field="status" data-index="' + i + '" value="' + htmlEscape(status) + '" style="width:100%;max-width:460px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
                  + '<div style="font-size:12px;color:#64748b;margin-top:4px;">Accepts mixed list of explicit http codes and classes "200, 301, 4xx, 5xx"</div>'
                  + '<div data-kind="' + kind + '" data-error="status" data-index="' + i + '" style="display:none;font-size:12px;color:#b91c1c;margin-top:4px;"></div>'
                  + '</div>')
                : '')
              + '<label style="display:flex;gap:8px;align-items:center;margin:10px 0 6px;">'
              + '<input type="checkbox" class="rule-match-toggle" data-kind="' + kind + '" data-index="' + i + '" data-target="' + headersTarget + '"' + (headersEnabled ? ' checked' : '') + ' />'
              + '<span>Match On Header(s)</span>'
              + '</label>'
              + '<div id="' + headersTarget + '" style="display:' + (headersEnabled ? 'block' : 'none') + ';">'
              + '<div style="margin:6px 0 4px;">List of headers</div>'
              + renderHeaderList('rule-' + kind + '-' + i, {
                label: 'Headers',
                helpText: 'YAML-style: Header-Name: value per line',
                disabled: false,
                rows: 4,
                placeholder: 'Header-Name: value',
                value: headerValue,
              })
              + '</div>'
              + '<label style="display:block;margin:8px 0 4px;">JSONata Expression</label>'
              + '<textarea data-kind="' + kind + '" data-field="expr" data-index="' + i + '" rows="4" style="width:100%;max-width:740px;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">' + htmlEscape(rule.expr || '') + '</textarea>'
              + '<div style="margin-top:8px;"><a href="#" class="rule-remove-btn" data-kind="' + kind + '" data-index="' + i + '">Remove rule</a></div>'
              + '</div>';
          }).join('');
          rules.forEach((_, i) => {
            bindHeaderListToggles('rule-' + kind + '-' + i);
          });
        }
         function parseCsvList(v) {
           return String(v || '').split(',').map((s) => s.trim()).filter(Boolean);
         }
        function collectRuleDrafts(kind) {
          const listId = kind === 'outbound' ? 'outbound-rules-list' : 'inbound-rules-list';
          const rules = kind === 'outbound' ? outboundRuleDrafts : inboundRuleDrafts;
          const node = el(listId);
          if (!node) return rules;
          const next = [];
          for (let i = 0; i < rules.length; i += 1) {
            const get = (field) => node.querySelector('[data-kind="' + kind + '"][data-field="' + field + '"][data-index="' + i + '"]');
            const getToggle = (targetId) => node.querySelector('.rule-match-toggle[data-kind="' + kind + '"][data-index="' + i + '"][data-target="' + targetId + '"]');
            const name = (get('name')?.value || '').trim();
            const expr = get('expr')?.value || '';
            if (!name || !expr.trim()) continue;
            const headerEnabled = !!getToggle('rule-' + kind + '-' + i + '-headers')?.checked;
            let headers = [];
            if (headerEnabled) {
              const headersText = node.querySelector('#rule-' + kind + '-' + i + '-headers')?.value || '';
              const headersObj = headersMultilineToObject(headersText);
              headers = Object.entries(headersObj).map(([name, value]) => ({ name, value: String(value ?? '') }));
            }
            if (kind === 'outbound') {
              const methodEnabled = !!getToggle('rule-' + kind + '-' + i + '-method')?.checked;
              const methodRaw = get('method')?.value || '';
              const methodCheck = methodEnabled ? validateHttpMethodList(methodRaw) : { ok: true, value: [] };
              if (methodEnabled && !methodCheck.ok) {
                throw new Error(methodCheck.message);
              }
              const methodList = methodEnabled ? methodCheck.value : [];
              next.push({
                name,
                ...(methodEnabled && methodList.length ? { method: methodList } : {}),
                ...(headers.length ? { headers } : {}),
                expr,
              });
            } else {
              const statusEnabled = !!getToggle('rule-' + kind + '-' + i + '-status')?.checked;
              const statusRaw = get('status')?.value || '';
              const statusCheck = statusEnabled ? validateStatusList(statusRaw) : { ok: true, value: [] };
              if (statusEnabled && !statusCheck.ok) {
                throw new Error(statusCheck.message);
              }
              const statusList = statusEnabled ? statusCheck.value : [];
              next.push({
                name,
                ...(statusEnabled && statusList.length ? { status: statusList } : {}),
                ...(headers.length ? { headers } : {}),
                expr,
              });
            }
          }
          return next;
        }
        async function transformConfigLoad() {
          try {
            const payload = await apiCall(ADMIN_ROOT + '/transform-config', 'GET');
            const d = payload?.data || {};
            const enabled = d.enabled !== false;
            if (el('transform-global-enabled-outbound')) el('transform-global-enabled-outbound').checked = enabled;
            if (el('transform-global-enabled-inbound')) el('transform-global-enabled-inbound').checked = enabled;
            const outbound = d.outbound || {};
            const inbound = d.inbound || {};
            let headerMode = inbound?.header_filtering?.mode;
            let headerNames = Array.isArray(inbound?.header_filtering?.names) ? inbound.header_filtering.names : [];
            if (!headerMode && !headerNames.length) {
              try {
                const yamlText = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
                const parsed = parseInboundHeaderFilteringFromYaml(yamlText);
                if (parsed) {
                  headerMode = parsed.mode || headerMode;
                  headerNames = parsed.names || headerNames;
                } else {
                  const fallback = parseHeaderForwardingFromYaml(yamlText);
                  if (fallback) {
                    headerMode = fallback.mode || headerMode;
                    headerNames = fallback.names || headerNames;
                  }
                }
              } catch {
                // ignore config fallback errors
              }
            }
            if (el('inbound-header-filtering-mode')) el('inbound-header-filtering-mode').value = String(headerMode || 'blacklist');
            if (el('inbound-header-filtering-names')) {
              const names = Array.isArray(headerNames) ? headerNames.join(', ') : '';
              el('inbound-header-filtering-names').value = names;
            }
            updateInboundHeaderFilteringHelp(el('inbound-header-filtering-mode')?.value || 'blacklist');
            if (el('outbound-default-expr')) el('outbound-default-expr').value = String(outbound.defaultExpr || '');
            if (el('outbound-custom-js')) el('outbound-custom-js').value = outbound.custom_js_preprocessor || '';
            if (el('outbound-fallback')) el('outbound-fallback').value = String(outbound.fallback || 'passthrough');
            if (el('inbound-default-expr')) el('inbound-default-expr').value = String(inbound.defaultExpr || '');
            if (el('inbound-fallback')) el('inbound-fallback').value = String(inbound.fallback || 'passthrough');
            outboundRuleDrafts = Array.isArray(outbound.rules) ? outbound.rules.map(normalizeRuleForUi) : [];
            inboundRuleDrafts = Array.isArray(inbound.rules) ? inbound.rules.map(normalizeRuleForUi) : [];
            renderTransformRules('outbound');
            renderTransformRules('inbound');
            clearDirty('outbound-transform');
            clearDirty('inbound-transform');
          } catch (e) {
            // no-op: keep UI clean
          }
        }
        async function saveTransformConfig(kind) {
           try {
             const globalEnabled = !!(el('transform-global-enabled-outbound')?.checked || el('transform-global-enabled-inbound')?.checked);
             const outboundRules = collectRuleDrafts('outbound');
             const inboundRules = collectRuleDrafts('inbound');
            const inboundCustomEl = el('inbound-custom-js');
            const payload = {
              enabled: globalEnabled,
              outbound: {
                enabled: true,
                custom_js_preprocessor: (el('outbound-custom-js')?.value || '').trim() || null,
                defaultExpr: el('outbound-default-expr')?.value || '',
                fallback: el('outbound-fallback')?.value || 'passthrough',
                rules: outboundRules,
              },
              inbound: {
                enabled: true,
                ...(inboundCustomEl ? { custom_js_preprocessor: (inboundCustomEl.value || '').trim() || null } : {}),
                defaultExpr: el('inbound-default-expr')?.value || '',
                fallback: el('inbound-fallback')?.value || 'passthrough',
                header_filtering: {
                  mode: (el('inbound-header-filtering-mode')?.value || 'blacklist'),
                  names: parseCsvList(el('inbound-header-filtering-names')?.value || ''),
                },
                rules: inboundRules,
              },
            };
            const out = await apiCall(ADMIN_ROOT + '/transform-config', 'PUT', payload);
            if (kind === 'outbound') setOutput('headers-output', out);
            else setOutput('inbound-transform-output', out);
            await transformConfigLoad();
            clearDirty(kind === 'outbound' ? 'outbound-transform' : 'inbound-transform');
          } catch (e) {
            if (kind === 'outbound') setOutput('headers-output', String(e.message || e));
            else setOutput('inbound-transform-output', String(e.message || e));
          }
        }
         function sandboxUpdateAuthValueVisibility() {
           const mode = el('sandbox-auth-mode')?.value || 'admin_token';
           const wrap = el('sandbox-auth-value-wrap');
           if (!wrap) return;
           const needsValue = mode === 'admin_key' || mode === 'proxy_key' || mode === 'issuer_key';
           wrap.style.display = needsValue ? 'block' : 'none';
         }
         function sandboxRedactHeader(name, value) {
           const n = String(name || '').toLowerCase();
           if (SANDBOX_REDACT_HEADERS.has(n)) return '<REDACTED>';
           if (n.includes('token') || n.includes('secret') || n.includes('key')) return '<REDACTED>';
           return String(value ?? '');
         }
         function shellQuote(value) {
           return "'" + String(value ?? '').replace(/'/g, "'\\''") + "'";
         }
         function sandboxBuildCurl(method, url, headers, bodyText) {
           const lines = [];
           const m = String(method || 'GET').toUpperCase();
           const headerEntries = Object.entries(headers || {});
           const includeBody = m !== 'GET' && m !== 'HEAD' && String(bodyText || '').length > 0;
           if (includeBody && !headerEntries.some(([k]) => String(k).toLowerCase() === 'content-type')) {
             headerEntries.push(['Content-Type', 'application/json']);
           }
           lines.push('curl -sS -X ' + m + ' ' + shellQuote(url) + ' \\');
           headerEntries.forEach(([name, value]) => {
             lines.push('  -H ' + shellQuote(name + ': ' + sandboxRedactHeader(name, value)) + ' \\');
           });
           if (includeBody) {
             lines.push('  --data-binary ' + shellQuote(String(bodyText)));
           } else if (lines.length > 0) {
             const last = lines[lines.length - 1];
             if (last.endsWith(' \\')) lines[lines.length - 1] = last.slice(0, -2);
           }
           return lines.join('\n');
         }
         function sandboxTemplateUrl(tpl) {
           const path = String(tpl?.path || '').trim();
           if (!path) return (window.location.origin || '') + SANDBOX_API_PREFIX;
           if (path.startsWith('http://') || path.startsWith('https://')) return path;
           const base = window.location.origin || '';
           return base + path;
         }
         function sandboxRenderTemplates() {
           const node = el('sandbox-template');
           if (!node) return;
           const entries = Object.entries(SANDBOX_TEMPLATES);
           node.innerHTML = entries
             .map(([key, tpl]) => '<option value="' + key + '">' + htmlEscape(tpl.label || key) + '</option>')
             .join('');
         }
         function sandboxApplyTemplate(key) {
           const tpl = SANDBOX_TEMPLATES[key];
           if (!tpl) return;
           sandboxTemplateKey = key;
           if (el('sandbox-auth-mode')) el('sandbox-auth-mode').value = tpl.auth_mode || 'admin_token';
           sandboxUpdateAuthValueVisibility();
           const headers = tpl.headers && typeof tpl.headers === 'object' && !Array.isArray(tpl.headers) ? tpl.headers : {};
           let bodyObj = null;
           if (tpl.body == null) {
             bodyObj = { type: 'none' };
           } else if (typeof tpl.body === 'string') {
             bodyObj = { type: 'raw', raw: tpl.body };
           } else {
             bodyObj = { type: 'json', value: tpl.body };
           }
           setRequestForm('sandbox', {
             method: tpl.method || 'GET',
             url: sandboxTemplateUrl(tpl),
             headers,
             body: bodyObj,
           });
           setOutput('sandbox-request', 'Template selected: ' + (tpl.label || key));
           sandboxPreviewRequest();
         }
         function sandboxBuildAuthHeader(mode, value) {
           const v = String(value || '').trim();
           if (mode === 'none') return {};
           if (mode === 'admin_token') return currentKey ? { Authorization: 'Bearer ' + currentKey } : {};
           if (mode === 'admin_key') return v ? { 'X-Admin-Key': v } : {};
           if (mode === 'proxy_key') return v ? { 'X-Proxy-Key': v } : {};
           if (mode === 'issuer_key') return v ? { 'X-Issuer-Key': v } : {};
           return {};
         }
         function sandboxComputeRequestPreview() {
           const method = String(el('sandbox-verb')?.value || 'GET').toUpperCase();
           const authMode = el('sandbox-auth-mode')?.value || 'admin_token';
           const authValue = el('sandbox-auth-value')?.value || '';
           const url = String(el('sandbox-url')?.value || '').trim();
           const extraHeaders = headersMultilineToObject(el('sandbox-headers')?.value || '');
           const headers = { ...extraHeaders, ...sandboxBuildAuthHeader(authMode, authValue) };
           const bodyText = el('sandbox-body')?.value ?? '';
           return { method, url, headers, bodyText };
         }
        function sandboxPreviewRequest() {
          try {
            const req = sandboxComputeRequestPreview();
            setOutput('sandbox-request', sandboxBuildCurl(req.method, req.url, req.headers, req.bodyText));
          } catch (e) {
            setOutput('sandbox-request', String(e.message || e));
          }
        }
         async function sandboxSend() {
           try {
              const req = sandboxComputeRequestPreview();
              const method = req.method;
              const url = req.url;
              if (!url) throw new Error('Request URL is required.');
              const headers = req.headers;
              const bodyText = req.bodyText;
              setOutput('sandbox-request', sandboxBuildCurl(method, url, headers, bodyText));
             const init = {
               method,
               headers: { ...headers },
             };
             if (method !== 'GET' && method !== 'HEAD') {
               init.body = bodyText || '';
             }
             const res = await fetch(url, init);
             const text = await res.text();
             let parsed = null;
             try { parsed = JSON.parse(text); } catch {}
             setOutput('sandbox-response', {
               status: res.status,
               headers: Object.fromEntries(res.headers.entries()),
               body: parsed ?? text,
             });
           } catch (e) {
             setOutput('sandbox-response', String(e.message || e));
           }
         }
         function sandboxInit() {
           if (!el('sandbox-verb') || !el('sandbox-url')) return;
           sandboxRenderTemplates();
           if (el('sandbox-template')) {
             const defaultKey = SANDBOX_TEMPLATES.request_passthrough ? 'request_passthrough' : Object.keys(SANDBOX_TEMPLATES)[0];
             el('sandbox-template').value = defaultKey;
             sandboxApplyTemplate(defaultKey);
           }
           sandboxUpdateAuthValueVisibility();
           sandboxPreviewRequest();
         }
        async function headersList() {
          try {
            const payload = await apiCall(ADMIN_ROOT + '/headers', 'GET');
            const names = Array.isArray(payload?.enriched_headers) ? payload.enriched_headers : [];
            if (!names.length) {
              setHtml('headers-list', '<div>(none)</div>');
            } else {
              const rows = names.map((name) =>
                '<tr>'
                + '<td style="padding:6px 8px;border-bottom:1px solid #eee;">' + name + '</td>'
                + '<td style="padding:6px 8px;border-bottom:1px solid #eee;text-align:right;">'
                + '<a href="#" class="delete-header-btn" data-name="' + name + '">Delete</a>'
                + '</td>'
                + '</tr>'
              );
              setHtml('headers-list',
                '<table style="width:100%;border-collapse:collapse;">'
                + '<thead><tr><th style="text-align:left;padding:6px 8px;border-bottom:1px solid #e2e8f0;">Header</th><th style="width:1%;padding:6px 8px;border-bottom:1px solid #e2e8f0;"></th></tr></thead>'
                + '<tbody>' + rows.join('') + '</tbody></table>'
              );
            }
            if (el('headers-output')) el('headers-output').textContent = '';
          } catch (e) {
            setOutput('headers-output', String(e.message || e));
          }
        }
        async function headersSave() {
          try {
            const text = el('headers-input-headers')?.value || '';
            const headersObj = headersMultilineToObject(text);
            const entries = Object.entries(headersObj);
            if (!entries.length) {
              setOutput('headers-output', 'Add at least one header entry.');
              return;
            }
            for (const [name, value] of entries) {
              const headerName = String(name || '').trim();
              const headerValue = String(value ?? '').trim();
              if (!headerName || !headerValue) {
                throw new Error('All header entries must include a key and value.');
              }
              await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(headerName), 'PUT', { value: headerValue });
            }
            setOutput('headers-output', 'Enrichments updated.');
            await headersList();
          }
          catch (e) { setOutput('headers-output', String(e.message || e)); }
        }
         async function headersDeleteConfirmed() {
           const name = String(pendingDeleteHeaderName || '').trim();
           if (!name) return;
           try {
             await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(name), 'DELETE');
             setOutput('headers-output', 'Enrichment deleted: ' + name);
             await headersList();
           } catch (e) {
             setOutput('headers-output', String(e.message || e));
           } finally {
             pendingDeleteHeaderName = '';
             el('delete-header-modal')?.close();
           }
         }
         function promptDeleteHeader(name) {
           pendingDeleteHeaderName = String(name || '');
           const text = el('delete-header-modal-text');
           if (text) text.textContent = 'Delete enrichment "' + pendingDeleteHeaderName + '"?';
           const modal = el('delete-header-modal');
           if (modal && typeof modal.showModal === 'function') {
             modal.showModal();
             return;
           }
           if (window.confirm('Delete enrichment "' + pendingDeleteHeaderName + '"?')) {
             headersDeleteConfirmed();
           } else {
             pendingDeleteHeaderName = '';
           }
         }
        async function keysRefresh() {
           try {
             const payload = await apiCall(ADMIN_ROOT + '/keys', 'GET');
             const proxy = payload?.data?.proxy || {};
             const issuer = payload?.data?.issuer || {};
             const admin = payload?.data?.admin || {};
             const formatCreatedAt = (ms) => {
               const n = Number(ms || 0);
               if (!n) return 'n/a';
               try { return new Date(n).toLocaleString(); } catch { return 'n/a'; }
             };
            const proxyHtml =
              '<div><b>Proxy key</b></div>'
              + '<div>Primary: ' + (proxy.primary_active ? 'active' : 'missing') + '</div>'
              + '<div>Primary created: ' + formatCreatedAt(proxy.proxy_primary_key_created_at) + '</div>'
              + '<div>Secondary overlap key: ' + (proxy.secondary_active ? 'active' : 'inactive') + '</div>'
              + '<div>Secondary created: ' + formatCreatedAt(proxy.proxy_secondary_key_created_at) + '</div>'
              + '<div>Expiry policy: ' + (proxy.expiry_seconds === null ? 'n/a' : String(proxy.expiry_seconds) + 's') + '</div>';
            const issuerHtml =
              '<div><b>Issuer key</b></div>'
              + '<div>Primary: ' + (issuer.primary_active ? 'active' : 'missing') + '</div>'
              + '<div>Primary created: ' + formatCreatedAt(issuer.issuer_primary_key_created_at) + '</div>'
              + '<div>Secondary overlap key: ' + (issuer.secondary_active ? 'active' : 'inactive') + '</div>'
              + '<div>Secondary created: ' + formatCreatedAt(issuer.issuer_secondary_key_created_at) + '</div>'
              + '<div>Expiry policy: ' + (issuer.expiry_seconds === null ? 'n/a' : String(issuer.expiry_seconds) + 's') + '</div>';
            const inboundHtml =
              proxyHtml
              + '<hr style="margin:10px 0;border:none;border-top:1px solid #eee;" />'
              + issuerHtml;
            const adminHtml =
              '<div><b>Admin key</b></div>'
               + '<div>Primary: ' + (admin.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(admin.admin_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (admin.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(admin.admin_secondary_key_created_at) + '</div>'
              + '<div>Expiry policy: ' + (admin.expiry_seconds === null ? 'n/a' : String(admin.expiry_seconds) + 's') + '</div>';
            if (el('keys-status-inbound')) setHtml('keys-status-inbound', proxyHtml);
            if (el('keys-status-admin')) setHtml('keys-status-admin', adminHtml);
            if (el('keys-status-issuer')) setHtml('keys-status-issuer', issuerHtml);
           } catch (e) {
             setOutput('keys-output', String(e.message || e));
           }
         }
         async function rotateProxy() {
           try {
             setOutput('keys-output', await apiCall(ADMIN_ROOT + '/keys/proxy/rotate', 'POST'));
             await keysRefresh();
           }
           catch (e) { setOutput('keys-output', String(e.message || e)); }
         }
         async function rotateIssuer() {
           try {
             setOutput('issuer-keys-output', await apiCall(ADMIN_ROOT + '/keys/issuer/rotate', 'POST'));
             await keysRefresh();
           }
           catch (e) { setOutput('issuer-keys-output', String(e.message || e)); }
         }
        async function rotateAdmin() {
          try {
            const out = await apiCall(ADMIN_ROOT + '/keys/admin/rotate', 'POST');
            setOutput('keys-output', out);
            setOutput('admin-keys-output', out);
            await keysRefresh();
            setCurrentKey('');
            showWarning('Admin key rotated. Re-enter the new admin key from response.');
          } catch (e) {
            setOutput('keys-output', String(e.message || e));
          }
        }

        function bind() {
          attachTabs();
          updateProxyHeader('');
          if (el('sandbox-request-form')) {
            setHtml('sandbox-request-form', renderRequestForm('sandbox'));
            bindRequestFormToggles('sandbox');
          }
          if (el('kr-request-form')) {
            setHtml('kr-request-form', renderRequestForm('kr', {
              enableHttpAuthorization: true,
              authProfileHint: 'Use a configured profile such as target.',
            }));
            bindRequestFormToggles('kr');
          }
          if (el('jwt-jwks-request-form')) {
            setHtml('jwt-jwks-request-form', renderRequestForm('jwt-jwks', {
              enableHttpAuthorization: true,
              authProfileHint: 'Use a configured profile such as jwt_inbound.',
            }));
            bindRequestFormToggles('jwt-jwks');
          }
          if (el('logging-request-form')) {
            setHtml('logging-request-form', renderRequestForm('logging-req', {
              enableHttpAuthorization: true,
              authProfileHint: 'Use a configured profile such as logging.',
            }));
            bindRequestFormToggles('logging-req');
          }
          if (el('jwt-endpoint-url')) el('jwt-endpoint-url').value = window.location.origin + '/_apiproxy/jwt';
          document.querySelectorAll('.tab-panel').forEach((panel) => {
            const name = panel.id.replace('tab-', '');
            if (name === 'sandbox') return;
            panel.addEventListener('input', () => markDirty(name));
            panel.addEventListener('change', () => markDirty(name));
          });
          el('login-btn')?.addEventListener('click', async () => {
             const adminKey = readKeyInput();
             if (!adminKey) {
               showWarning('Enter an admin key first.');
               return;
             }
             try {
               const res = await fetch(ADMIN_ROOT + '/access-token', {
                 method: 'POST',
                 headers: { 'X-Admin-Key': adminKey },
               });
               if (!res.ok) {
                 const text = await res.text();
                 throw new Error('Login failed: ' + text);
               }
               const payload = await res.json();
               const token = String(payload?.data?.access_token || '');
               if (!token) {
                 throw new Error('Login failed: access token missing');
               }
               try { sessionStorage.setItem(ADMIN_ACCESS_TOKEN_STORAGE, token); } catch {}
               setCurrentKey(token);
               showWarning('');
              try {
                await refreshOverview();
                await debugLoadTrace();
                await loadLoggingStatus();
                await configLoad();
                await keyRotationLoad();
                await transformConfigLoad();
                await headersList();
                await keysRefresh();
                addHeaderInputRow('', '');
              } catch {
                // no-op
              }
             } catch (e) {
               showWarning(String(e.message || e));
             }
           });
          el('logout-link')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            logoutExplicit();
          });
           el('overview-refresh-btn')?.addEventListener('click', refreshOverview);
          el('debug-refresh-trace-link')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            debugLoadTrace();
          });
          el('live-log-reconnect-link')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            stopLiveLogStream();
            loadLiveLogStatusAndMaybeConnect();
          });
          el('live-log-clear-link')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            if (el('live-log-output')) el('live-log-output').textContent = '';
          });
          el('logging-ttl-refresh-link')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            loadLoggingStatus();
          });
          el('logging-status')?.addEventListener('click', (evt) => {
            const link = evt.target;
            if (!link || !link.id) return;
            if (link.id === 'logging-enable-link') {
              evt.preventDefault();
              debugEnable();
            }
            if (link.id === 'logging-disable-link') {
              evt.preventDefault();
              debugDisable();
            }
          });
          el('logging-config-enabled')?.addEventListener('change', () => {
            const enabled = !!el('logging-config-enabled')?.checked;
            if (el('logging-config-fields')) el('logging-config-fields').style.display = enabled ? 'block' : 'none';
          });
           el('logging-open-config-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             openConfigTab();
           });
           el('logging-open-config-link-label')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             openConfigTab();
           });
           el('logging-open-config-link-header')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             openConfigTab();
           });
          el('footer-save-logging')?.addEventListener('click', loggingSave);
           el('config-reload-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             configLoad();
           });
           el('config-test-rule-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             configTestRule();
           });
          el('footer-save-config')?.addEventListener('click', configSave);
          el('footer-save-outbound-auth')?.addEventListener('click', keyRotationSave);
           el('outbound-auth-enabled')?.addEventListener('change', () => {
             setOutboundAuthEnabled(!!el('outbound-auth-enabled')?.checked);
           });
          el('jwt-enabled')?.addEventListener('change', () => {
            setJwtEnabled(!!el('jwt-enabled')?.checked);
          });
          el('jwt-inbound-enabled')?.addEventListener('change', () => {
            setJwtInboundEnabled(!!el('jwt-inbound-enabled')?.checked);
          });
          el('jwt-outbound-enabled')?.addEventListener('change', () => {
            setJwtOutboundEnabled(!!el('jwt-outbound-enabled')?.checked);
          });
          el('jwt-inbound-mode')?.addEventListener('change', () => {
            updateJwtModeFields(el('jwt-inbound-mode')?.value || 'shared_secret');
          });
          el('inbound-header-filtering-mode')?.addEventListener('change', () => {
            updateInboundHeaderFilteringHelp(el('inbound-header-filtering-mode')?.value || 'blacklist');
          });
          el('config-yaml')?.addEventListener('input', () => {
            setConfigSaveEnabled(false);
            if (configValidateTimer) clearTimeout(configValidateTimer);
            configValidateTimer = setTimeout(() => { configValidate(false); }, 350);
          });
          el('config-yaml')?.addEventListener('blur', () => configValidate(true));
          el('proxy-name')?.addEventListener('input', () => {
            updateProxyHeader(el('proxy-name')?.value || '');
            setConfigSaveEnabled(false);
            markDirty('config');
          });
          el('proxy-name')?.addEventListener('blur', () => configValidate(true));
           el('headers-save-btn')?.addEventListener('click', headersSave);
          el('headers-list')?.addEventListener('click', (evt) => {
            const target = evt.target?.closest ? evt.target.closest('.delete-header-btn') : null;
            if (!target) return;
            evt.preventDefault();
            const name = target.getAttribute('data-name') || '';
            promptDeleteHeader(name);
          });
           el('outbound-add-rule-btn')?.addEventListener('click', () => {
             outboundRuleDrafts.push(emptyOutboundRule());
             renderTransformRules('outbound');
           });
           el('inbound-add-rule-btn')?.addEventListener('click', () => {
             inboundRuleDrafts.push(emptyInboundRule());
             renderTransformRules('inbound');
           });
        function handleRuleListClick(kind, evt) {
            const removeRuleBtn = evt.target?.closest ? evt.target.closest('.rule-remove-btn') : null;
            if (removeRuleBtn && removeRuleBtn.getAttribute('data-kind') === kind) {
              evt.preventDefault();
              const idx = Number(removeRuleBtn.getAttribute('data-index') || -1);
              if (idx >= 0) {
                if (kind === 'outbound') outboundRuleDrafts.splice(idx, 1);
                else inboundRuleDrafts.splice(idx, 1);
                renderTransformRules(kind);
              }
              return;
            }
          }
          el('outbound-rules-list')?.addEventListener('click', (evt) => handleRuleListClick('outbound', evt));
          el('inbound-rules-list')?.addEventListener('click', (evt) => handleRuleListClick('inbound', evt));
          function handleRuleToggle(evt) {
            const toggle = evt.target;
            if (!toggle || !toggle.classList || !toggle.classList.contains('rule-match-toggle')) return;
            const targetId = toggle.getAttribute('data-target');
            if (!targetId) return;
            const panel = document.getElementById(targetId);
            if (panel) panel.style.display = toggle.checked ? 'block' : 'none';
          }
          el('outbound-rules-list')?.addEventListener('change', handleRuleToggle);
          el('inbound-rules-list')?.addEventListener('change', handleRuleToggle);
          function handleRuleInputValidation(evt) {
            const target = evt.target;
            if (!target) return;
            const kind = target.getAttribute('data-kind');
            const idx = Number(target.getAttribute('data-index') || -1);
            if (!kind || idx < 0) return;
            if (target.getAttribute('data-field') === 'method') {
              const res = validateHttpMethodList(target.value || '');
              const msg = (kind && res.ok) ? '' : res.message;
              const errorNode = document.querySelector('[data-kind="' + kind + '"][data-error="method"][data-index="' + idx + '"]');
              if (errorNode) {
                errorNode.textContent = msg || '';
                errorNode.style.display = msg ? 'block' : 'none';
              }
              target.style.borderColor = msg ? '#dc2626' : '#cbd5e1';
            }
            if (target.getAttribute('data-field') === 'status') {
              const res = validateStatusList(target.value || '');
              const msg = (kind && res.ok) ? '' : res.message;
              const errorNode = document.querySelector('[data-kind="' + kind + '"][data-error="status"][data-index="' + idx + '"]');
              if (errorNode) {
                errorNode.textContent = msg || '';
                errorNode.style.display = msg ? 'block' : 'none';
              }
              target.style.borderColor = msg ? '#dc2626' : '#cbd5e1';
            }
            if (target.getAttribute('data-field') === 'headerName' || target.getAttribute('data-field') === 'headerValue') {
              updateHeaderAddButton(kind, idx);
            }
          }
          el('outbound-rules-list')?.addEventListener('input', handleRuleInputValidation);
          el('inbound-rules-list')?.addEventListener('input', handleRuleInputValidation);
           el('footer-save-outbound-transform')?.addEventListener('click', () => saveTransformConfig('outbound'));
           el('footer-save-inbound-transform')?.addEventListener('click', () => saveTransformConfig('inbound'));
           el('transform-global-enabled-outbound')?.addEventListener('change', () => {
             const v = !!el('transform-global-enabled-outbound')?.checked;
             if (el('transform-global-enabled-inbound')) el('transform-global-enabled-inbound').checked = v;
           });
           el('transform-global-enabled-inbound')?.addEventListener('change', () => {
             const v = !!el('transform-global-enabled-inbound')?.checked;
             if (el('transform-global-enabled-outbound')) el('transform-global-enabled-outbound').checked = v;
           });
           el('delete-header-cancel-btn')?.addEventListener('click', () => {
             pendingDeleteHeaderName = '';
             el('delete-header-modal')?.close();
           });
           el('delete-header-confirm-btn')?.addEventListener('click', headersDeleteConfirmed);
          el('keys-refresh-link-inbound')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            keysRefresh();
          });
          el('keys-refresh-link-issuer')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            keysRefresh();
          });
          el('keys-refresh-link-admin')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            keysRefresh();
          });
          el('footer-save-inbound-auth')?.addEventListener('click', inboundAuthSave);
          el('footer-save-admin-auth')?.addEventListener('click', adminAuthSave);
          el('jwt-enabled')?.addEventListener('change', () => {
            setJwtEnabled(!!el('jwt-enabled')?.checked);
          });
           el('rotate-proxy-btn')?.addEventListener('click', rotateProxy);
           el('rotate-issuer-btn')?.addEventListener('click', rotateIssuer);
           el('rotate-admin-btn')?.addEventListener('click', rotateAdmin);
          el('sandbox-template')?.addEventListener('change', (evt) => {
            const key = evt.target?.value || '';
            if (key) sandboxApplyTemplate(String(key));
          });
          el('sandbox-verb')?.addEventListener('change', sandboxPreviewRequest);
          el('sandbox-auth-mode')?.addEventListener('change', () => {
            sandboxUpdateAuthValueVisibility();
            sandboxPreviewRequest();
          });
          el('sandbox-auth-value')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-url')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-headers')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-body')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-send-btn')?.addEventListener('click', sandboxSend);
           try {
             const token = sessionStorage.getItem(ADMIN_ACCESS_TOKEN_STORAGE) || '';
            if (token) {
              setCurrentKey(token);
              refreshOverview();
              debugLoadTrace();
              loadLoggingStatus();
              configLoad();
              keyRotationLoad();
              transformConfigLoad();
              headersList();
              keysRefresh();
              sandboxInit();
              addHeaderInputRow('', '');
            }
           } catch {}
         }
         bind();

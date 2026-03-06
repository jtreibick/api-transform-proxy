         const ADMIN_ROOT = '/_apiproxy/admin';
         const ADMIN_ACCESS_TOKEN_STORAGE = 'apiproxy_admin_access_token_v1';
         let currentKey = '';
        let pendingDeleteHeaderName = '';
        let configValidateTimer = null;
        let sandboxTemplateKey = '';
        let sandboxSyncingControls = false;
        let outboundRuleDrafts = [];
        let inboundRuleDrafts = [];
        let currentTabName = 'overview';
        const dirtyTabs = new Set();
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
        function updateProxyHeader(proxyName) {
          const host = window.location.host || '';
          const name = String(proxyName || '').trim();
          const subtitle = host + (name ? ' (' + name + ')' : '');
          if (el('proxy-subtitle')) el('proxy-subtitle').textContent = subtitle;
        }
        function openConfigTab() {
          document.querySelector('.tab-btn[data-tab="config"]')?.click();
        }
        function setOutboundMode(mode) {
          const m = String(mode || 'static_header').trim();
          const staticNode = el('outbound-static-fields');
          const autoNode = el('outbound-auto-fields');
          const isStatic = m === 'static_header';
           if (staticNode) staticNode.style.display = isStatic ? 'block' : 'none';
           if (autoNode) autoNode.style.display = isStatic ? 'none' : 'block';
         }
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
             showWarning('');
              return;
            }
         }
         function handleUnauthorized() {
            currentKey = '';
            try { sessionStorage.removeItem(ADMIN_ACCESS_TOKEN_STORAGE); } catch {}
            if (el('admin-key')) el('admin-key').value = '';
            if (el('admin-shell')) el('admin-shell').style.display = 'none';
            if (el('admin-auth')) el('admin-auth').style.display = 'block';
            showWarning('Session logged out. Provide admin key again to login.');
         }
        async function apiCall(path, method, body, expectText) {
          if (!currentKey) {
            throw new Error('Login first.');
           }
           if (UI_DEBUG) {
             const safeBody = (path.includes('/config') || typeof body === 'string') ? '(redacted)' : body;
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
        function attachTabs() {
          const btns = document.querySelectorAll('.tab-btn');
          const panels = document.querySelectorAll('.tab-panel');
          function setActiveTab(name) {
            if (name === currentTabName) return;
            if (!confirmLeaveDirty(currentTabName)) return;
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
               debugLoadTrace();
               loadLoggingStatus();
             }
             if (name === 'outbound-auth') keyRotationLoad();
            if (name === 'outbound-transform') {
              transformConfigLoad();
              headersList();
              if (el('headers-input-body') && !el('headers-input-body').children.length) {
                addHeaderInputRow('', '');
              }
            }
            if (name === 'admin-auth') {
              keysRefresh();
            }
            if (name === 'inbound-auth') {
              keyRotationLoad();
              keysRefresh();
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
            + '<div><b>Build Version:</b> ' + versionText + '</div>'
            + '<div><b>Last Deployed:</b> ' + (buildTimestamp || 'n/a') + '</div>'
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
             setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug', 'PUT', { enabled: true, ttl_seconds: ttl }));
             await loadLoggingStatus();
           }
           catch (e) { setOutput('logging-output', String(e.message || e)); }
         }
         async function debugDisable() {
           try {
             setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug', 'DELETE'));
             await loadLoggingStatus();
           }
           catch (e) { setOutput('logging-output', String(e.message || e)); }
         }
         async function debugLoadTrace() {
           try { setOutput('debug-output', await apiCall(ADMIN_ROOT + '/debug/last', 'GET', undefined, true)); }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
        async function loggingSecretSave() {
          try {
            const payload = { value: el('logging-secret')?.value || '' };
            setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug/loggingSecret', 'PUT', payload));
            await loadLoggingStatus();
            clearDirty('debug');
          } catch (e) {
            setOutput('logging-output', String(e.message || e));
          }
        }
         async function loggingSecretDelete() {
           try {
             setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug/loggingSecret', 'DELETE'));
             await loadLoggingStatus();
           }
           catch (e) { setOutput('logging-output', String(e.message || e)); }
         }
         async function loadLoggingStatus() {
           try {
             const [debugStatus, secretStatus, yamlText] = await Promise.all([
               apiCall(ADMIN_ROOT + '/debug', 'GET'),
               apiCall(ADMIN_ROOT + '/debug/loggingSecret', 'GET'),
               apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true),
             ]);
            let endpointUrl = '';
            let endpointAuthHeader = '';
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
                endpointUrl = cfg.url || '';
                endpointAuthHeader = cfg.auth_header || '';
               }
             } catch {}
            if (el('logging-config-url')) el('logging-config-url').value = endpointUrl;
            if (el('logging-config-auth-header')) el('logging-config-auth-header').value = endpointAuthHeader;
            const d = debugStatus?.data || {};
            const enabledText = d.enabled ? 'enabled' : 'disabled';
            if (el('logging-status')) {
              const html = d.enabled
                ? '<div style="background:#fef9c3;border:1px solid #fde68a;color:#92400e;padding:8px 10px;border-radius:8px;margin-bottom:6px;">Logging is enabled.</div>'
                  + '<a href="#" id="logging-disable-link">disable</a> | ' + enabledText
                : enabledText + ' | <a href="#" id="logging-enable-link">enable</a>';
              setHtml('logging-status', html);
            }
            const ttlRemaining = Number.isFinite(Number(d.ttl_remaining_seconds)) ? Number(d.ttl_remaining_seconds) : null;
            if (el('logging-ttl-remaining')) {
              el('logging-ttl-remaining').textContent = ttlRemaining === null ? 'n/a' : String(ttlRemaining);
            }
            if (el('logging-ttl-remaining-2')) {
              el('logging-ttl-remaining-2').textContent = ttlRemaining === null ? 'n/a' : String(ttlRemaining);
            }
            if (el('logging-ttl-seconds') && Number(d.max_ttl_seconds || 0) > 0 && !el('logging-ttl-seconds').value) {
              el('logging-ttl-seconds').value = String(Number(d.max_ttl_seconds));
            }
            const configEnabled = !!(endpointUrl || endpointAuthHeader);
            if (el('logging-config-enabled')) el('logging-config-enabled').checked = configEnabled;
            if (el('logging-config-fields')) el('logging-config-fields').style.display = configEnabled ? 'block' : 'none';
            if (el('logging-secret-wrap')) el('logging-secret-wrap').style.display = configEnabled ? 'block' : 'none';
            const secretSet = !!secretStatus?.data?.logging_secret_set;
            setOutput('logging-output', 'Logging secret set: ' + (secretSet ? 'yes' : 'no'));
          } catch (e) {
            setOutput('logging-output', String(e.message || e));
          }
        }
        async function configLoad() {
          try {
            const text = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
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
             const [payload, headersPayload] = await Promise.all([
               apiCall(ADMIN_ROOT + '/key-rotation-config', 'GET'),
               apiCall(ADMIN_ROOT + '/headers', 'GET'),
             ]);
             const d = payload?.data || {};
             const names = Array.isArray(headersPayload?.enriched_headers) ? headersPayload.enriched_headers : [];
             const inferredStaticKey = names.includes('authorization') ? 'authorization' : (names[0] || '');
             const staticHeaderKey = String(d.static_header_key || inferredStaticKey || '');
             const staticHeaderValue = String(d.static_header_value || '');
          const outboundMode = staticHeaderKey ? 'static_header' : 'autorotation';
            if (el('outbound-mode')) el('outbound-mode').value = outboundMode || 'static_header';
            if (el('outbound-static-header-key')) el('outbound-static-header-key').value = staticHeaderKey;
            if (el('outbound-static-header-value')) el('outbound-static-header-value').value = staticHeaderValue;
            setOutboundMode(outboundMode || 'static_header');
             setOutboundAuthEnabled(!!d.enabled);
             if (el('kr-enabled')) el('kr-enabled').checked = !!d.enabled;
             if (el('kr-strategy')) el('kr-strategy').value = d.strategy || 'json_ttl';
             if (el('kr-request-yaml')) el('kr-request-yaml').value = String(d.request_yaml || '');
             if (el('kr-key-path')) el('kr-key-path').value = String(d.key_path || '');
             if (el('kr-ttl-path')) el('kr-ttl-path').value = d.ttl_path == null ? '' : String(d.ttl_path);
             if (el('kr-ttl-unit')) el('kr-ttl-unit').value = d.ttl_unit || 'seconds';
             if (el('kr-expires-at-path')) el('kr-expires-at-path').value = d.expires_at_path == null ? '' : String(d.expires_at_path);
             if (el('kr-refresh-skew')) el('kr-refresh-skew').value = String(Number(d.refresh_skew_seconds || 0));
             if (el('kr-retry-on-401')) el('kr-retry-on-401').checked = !!d.retry_once_on_401;
            if (el('kr-proxy-expiry')) el('kr-proxy-expiry').value = d.proxy_expiry_seconds == null ? '' : String(d.proxy_expiry_seconds);
            if (el('kr-issuer-expiry')) el('kr-issuer-expiry').value = d.issuer_expiry_seconds == null ? '' : String(d.issuer_expiry_seconds);
            if (el('kr-admin-expiry')) el('kr-admin-expiry').value = d.admin_expiry_seconds == null ? '' : String(d.admin_expiry_seconds);
            setOutput('kr-output', 'Outbound auth configuration loaded.');
            clearDirty('outbound-auth');
          } catch (e) {
            setOutput('kr-output', String(e.message || e));
          }
        }
         async function keyRotationSave() {
           try {
             const outboundAuthEnabled = !!el('outbound-auth-enabled')?.checked;
             if (el('kr-enabled')) el('kr-enabled').checked = outboundAuthEnabled;
             const mode = (el('outbound-mode')?.value || 'autorotation');
             const staticHeaderKey = (el('outbound-static-header-key')?.value || '').trim();
             const staticHeaderValue = el('outbound-static-header-value')?.value || '';
             if (mode === 'static_header') {
               if (!outboundAuthEnabled) {
                 setOutput('kr-output', 'Outbound auth disabled.');
                 return;
               }
               if (!staticHeaderKey || !staticHeaderValue) {
                 throw new Error('Static header key and secret value are required.');
               }
              await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(staticHeaderKey), 'PUT', { value: staticHeaderValue });
              setOutput('kr-output', 'Saved static outbound auth header: ' + staticHeaderKey);
              await headersList();
              clearDirty('outbound-auth');
              return;
            }
             const payload = {
               enabled: outboundAuthEnabled,
               strategy: (el('kr-strategy')?.value || 'json_ttl'),
               request_yaml: el('kr-request-yaml')?.value || '',
               key_path: el('kr-key-path')?.value || '',
               ttl_path: el('kr-ttl-path')?.value || null,
               ttl_unit: el('kr-ttl-unit')?.value || 'seconds',
               expires_at_path: el('kr-expires-at-path')?.value || null,
               refresh_skew_seconds: Number(el('kr-refresh-skew')?.value || 0),
               retry_once_on_401: !!el('kr-retry-on-401')?.checked,
             };
            const out = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'PUT', payload);
            setOutput('kr-output', out);
            clearDirty('outbound-auth');
          } catch (e) {
            setOutput('kr-output', String(e.message || e));
          }
        }
        async function inboundAuthSave() {
          try {
            const current = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'GET');
            const d = current?.data || {};
            const payload = {
              enabled: !!d.enabled,
              strategy: d.strategy || 'json_ttl',
              request_yaml: d.request_yaml || '',
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
              request_yaml: d.request_yaml || '',
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
        function hasHeaderRowErrors(headers) {
          return (headers || []).some((h) => !String(h?.name || '').trim() || !String(h?.value || '').trim());
        }
        function renderHeaderRows(kind, ruleIndex, headers) {
          const safeHeaders = Array.isArray(headers) ? headers : [];
          if (!safeHeaders.length) {
            return '<div style="color:#64748b;margin:6px 0;">(no header matches)</div>';
          }
          return '<table style="width:100%;border-collapse:collapse;">'
            + '<thead><tr>'
            + '<th style="text-align:left;padding:6px 8px;border-bottom:1px solid #e2e8f0;">Header Name</th>'
            + '<th style="text-align:left;padding:6px 8px;border-bottom:1px solid #e2e8f0;">Header Value</th>'
            + '<th style="width:1%;padding:6px 8px;border-bottom:1px solid #e2e8f0;"></th>'
            + '</tr></thead><tbody>'
            + safeHeaders.map((h, j) => {
            const name = htmlEscape(h?.name || '');
            const value = htmlEscape(h?.value || '');
            return '<tr>'
              + '<td style="padding:6px 8px;">'
              + '<input data-kind="' + kind + '" data-field="headerName" data-index="' + ruleIndex + '" data-header-index="' + j + '" value="' + name + '" placeholder="Header Name" style="width:100%;max-width:260px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
              + '</td>'
              + '<td style="padding:6px 8px;">'
              + '<input data-kind="' + kind + '" data-field="headerValue" data-index="' + ruleIndex + '" data-header-index="' + j + '" value="' + value + '" placeholder="Header Value" style="width:100%;max-width:360px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
              + '</td>'
              + '<td style="padding:6px 8px;text-align:right;">'
              + '<a href="#" class="rule-header-remove-btn" data-kind="' + kind + '" data-index="' + ruleIndex + '" data-header-index="' + j + '">Remove</a>'
              + '</td>'
              + '</tr>';
          }).join('')
          + '</tbody></table>';
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
            const disableHeaderAdd = hasHeaderRowErrors(headers);
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
              + renderHeaderRows(kind, i, headers)
              + '<div style="margin-top:8px;"><button type="button" class="rule-header-add-btn" data-kind="' + kind + '" data-index="' + i + '"' + (disableHeaderAdd ? ' disabled style="opacity:0.5;cursor:not-allowed;"' : '') + '>Add header match rule</button></div>'
              + '</div>'
              + '<label style="display:block;margin:8px 0 4px;">JSONata Expression</label>'
              + '<textarea data-kind="' + kind + '" data-field="expr" data-index="' + i + '" rows="4" style="width:100%;max-width:740px;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">' + htmlEscape(rule.expr || '') + '</textarea>'
              + '<div style="margin-top:8px;"><a href="#" class="rule-remove-btn" data-kind="' + kind + '" data-index="' + i + '">Remove rule</a></div>'
              + '</div>';
          }).join('');
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
            const headers = [];
            const headerEnabled = !!getToggle('rule-' + kind + '-' + i + '-headers')?.checked;
            if (headerEnabled) {
              const headerNodes = node.querySelectorAll('[data-kind="' + kind + '"][data-field="headerName"][data-index="' + i + '"]');
              headerNodes.forEach((input) => {
                const headerIndex = input.getAttribute('data-header-index');
                const nameInput = input;
                const valueInput = node.querySelector('[data-kind="' + kind + '"][data-field="headerValue"][data-index="' + i + '"][data-header-index="' + headerIndex + '"]');
                const hName = String(nameInput?.value || '').trim();
                const hValue = String(valueInput?.value || '').trim();
                if (hName && hValue) headers.push({ name: hName, value: hValue });
              });
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
            if (el('inbound-header-blacklist')) el('inbound-header-blacklist').value = String(inbound?.header_blacklist || '');
            if (el('outbound-default-expr')) el('outbound-default-expr').value = String(outbound.defaultExpr || '');
            if (el('outbound-fallback')) el('outbound-fallback').value = String(outbound.fallback || 'passthrough');
            if (el('inbound-default-expr')) el('inbound-default-expr').value = String(inbound.defaultExpr || '');
            if (el('inbound-fallback')) el('inbound-fallback').value = String(inbound.fallback || 'passthrough');
            outboundRuleDrafts = Array.isArray(outbound.rules) ? outbound.rules.map(normalizeRuleForUi) : [];
            inboundRuleDrafts = Array.isArray(inbound.rules) ? inbound.rules.map(normalizeRuleForUi) : [];
            renderTransformRules('outbound');
            renderTransformRules('inbound');
            setOutput('headers-output', 'Outbound transformations loaded.');
            setOutput('inbound-transform-output', 'Inbound transformations loaded.');
            clearDirty('outbound-transform');
            clearDirty('inbound-transform');
          } catch (e) {
            setOutput('headers-output', String(e.message || e));
            setOutput('inbound-transform-output', String(e.message || e));
          }
        }
        async function saveTransformConfig(kind) {
           try {
             const globalEnabled = !!(el('transform-global-enabled-outbound')?.checked || el('transform-global-enabled-inbound')?.checked);
             const outboundRules = collectRuleDrafts('outbound');
             const inboundRules = collectRuleDrafts('inbound');
            const payload = {
              enabled: globalEnabled,
              outbound: {
                enabled: true,
                defaultExpr: el('outbound-default-expr')?.value || '',
                fallback: el('outbound-fallback')?.value || 'passthrough',
                rules: outboundRules,
              },
              inbound: {
                enabled: true,
                defaultExpr: el('inbound-default-expr')?.value || '',
                fallback: el('inbound-fallback')?.value || 'passthrough',
                header_blacklist: el('inbound-header-blacklist')?.value || '',
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
        function addHeaderMatchRule(kind, ruleIndex) {
          const rules = kind === 'outbound' ? outboundRuleDrafts : inboundRuleDrafts;
          const rule = rules[ruleIndex];
          if (!rule) return;
          if (!Array.isArray(rule.headers)) rule.headers = [];
          rule.headers.push({ name: '', value: '' });
          renderTransformRules(kind);
        }
        function removeHeaderMatchRule(kind, ruleIndex, headerIndex) {
          const rules = kind === 'outbound' ? outboundRuleDrafts : inboundRuleDrafts;
          const rule = rules[ruleIndex];
          if (!rule || !Array.isArray(rule.headers)) return;
          rule.headers.splice(headerIndex, 1);
          renderTransformRules(kind);
        }
        function sandboxPathToSuffix(path) {
           if (path === SANDBOX_API_PREFIX) return '';
           if (path.startsWith(SANDBOX_API_PREFIX + '/')) return path.slice((SANDBOX_API_PREFIX + '/').length);
           return null;
         }
         function sandboxBuildUrlFromSelection() {
           const suffix = el('sandbox-path')?.value || '';
           const base = window.location.origin || '';
           return base + SANDBOX_API_PREFIX + (suffix ? '/' + suffix : '');
         }
         function sandboxUpdateBaseUrlDisplay() {
           const suffix = el('sandbox-path')?.value || '';
           const node = el('sandbox-base-url');
           if (!node) return;
           const base = window.location.origin || '';
           node.textContent = base + SANDBOX_API_PREFIX + (suffix ? '/' + suffix : '');
         }
         function sandboxUpdateAuthValueVisibility() {
           const mode = el('sandbox-auth-mode')?.value || 'admin_token';
           const wrap = el('sandbox-auth-value-wrap');
           if (!wrap) return;
           const needsValue = mode === 'admin_key' || mode === 'proxy_key' || mode === 'issuer_key';
           wrap.style.display = needsValue ? 'block' : 'none';
         }
         function sandboxSyncUrlFromSelection() {
           if (sandboxSyncingControls) return;
           const node = el('sandbox-url');
           if (node) node.value = sandboxBuildUrlFromSelection();
           sandboxUpdateBaseUrlDisplay();
           sandboxPreviewRequest();
         }
         function sandboxFindTemplate(method, suffix) {
           const m = String(method || '').toUpperCase();
           const s = String(suffix || '');
           const entries = Object.entries(SANDBOX_TEMPLATES);
           for (const [key, tpl] of entries) {
             const tplSuffix = sandboxPathToSuffix(String(tpl.path || ''));
             if (tplSuffix === null) continue;
             if (String(tpl.method || '').toUpperCase() === m && tplSuffix === s) {
               return { key, tpl };
             }
           }
          return null;
         }
         function sandboxMethodsForSuffix(suffix) {
           const s = String(suffix || '');
           const methods = Array.from(new Set(
             Object.values(SANDBOX_TEMPLATES)
               .filter((tpl) => sandboxPathToSuffix(String(tpl.path || '')) === s)
               .map((tpl) => String(tpl.method || '').toUpperCase())
               .filter(Boolean)
           ));
           return methods.sort();
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
         function sandboxRenderSelectors() {
           const verbNode = el('sandbox-verb');
           const pathNode = el('sandbox-path');
           const baseNode = el('sandbox-base-url');
           if (!verbNode || !pathNode) return;
           if (baseNode) baseNode.textContent = (window.location.origin || '') + SANDBOX_API_PREFIX;
           const paths = Array.from(new Set(
             Object.values(SANDBOX_TEMPLATES)
               .map((t) => sandboxPathToSuffix(String(t.path || '')))
               .filter((v) => v !== null)
           )).sort((a, b) => a.localeCompare(b));
           pathNode.innerHTML = paths.map((p) => {
             const label = p || '(root)';
             return '<option value="' + p + '">' + label + '</option>';
           }).join('');
           const initialSuffix = pathNode.value || paths[0] || '';
           const methods = sandboxMethodsForSuffix(initialSuffix);
           verbNode.innerHTML = methods.map((v) => '<option value="' + v + '">' + v + '</option>').join('');
         }
         function sandboxApplyTemplate(key) {
           const tpl = SANDBOX_TEMPLATES[key];
           if (!tpl) return;
           sandboxTemplateKey = key;
           const suffix = sandboxPathToSuffix(String(tpl.path || ''));
           if (suffix !== null) {
             sandboxSyncingControls = true;
             if (el('sandbox-path')) el('sandbox-path').value = suffix;
             const methods = sandboxMethodsForSuffix(suffix);
             if (el('sandbox-verb')) {
               el('sandbox-verb').innerHTML = methods.map((m) => '<option value="' + m + '">' + m + '</option>').join('');
               el('sandbox-verb').value = String(tpl.method || 'GET').toUpperCase();
             }
             sandboxSyncingControls = false;
             sandboxSyncUrlFromSelection();
           }
           if (el('sandbox-auth-mode')) el('sandbox-auth-mode').value = tpl.auth_mode || 'admin_token';
           sandboxUpdateAuthValueVisibility();
           if (el('sandbox-extra-headers')) el('sandbox-extra-headers').value = JSON.stringify(tpl.headers || {}, null, 2);
           if (el('sandbox-body')) {
             if (tpl.body == null) {
               el('sandbox-body').value = '';
             } else if (typeof tpl.body === 'string') {
               el('sandbox-body').value = tpl.body;
             } else {
               el('sandbox-body').value = JSON.stringify(tpl.body, null, 2);
             }
           }
           setOutput('sandbox-request', 'Template selected: ' + tpl.label);
         }
         function sandboxApplyTemplateForSelection() {
           const suffix = el('sandbox-path')?.value || '';
           const requestedMethod = el('sandbox-verb')?.value || '';
           const methods = sandboxMethodsForSuffix(suffix);
           if (el('sandbox-verb')) {
             el('sandbox-verb').innerHTML = methods.map((m) => '<option value="' + m + '">' + m + '</option>').join('');
             if (methods.includes(requestedMethod)) {
               el('sandbox-verb').value = requestedMethod;
             }
           }
           const method = el('sandbox-verb')?.value || methods[0] || 'GET';
           const match = sandboxFindTemplate(method, suffix);
           if (match) {
             sandboxApplyTemplate(match.key);
             return;
           }
           sandboxTemplateKey = '';
           sandboxSyncUrlFromSelection();
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
           const suffix = String(el('sandbox-path')?.value || '');
           const tplMatch = sandboxFindTemplate(method, suffix);
           const tpl = tplMatch ? tplMatch.tpl : null;
           const authMode = el('sandbox-auth-mode')?.value || 'admin_token';
           const authValue = el('sandbox-auth-value')?.value || '';
           const url = String(el('sandbox-url')?.value || sandboxBuildUrlFromSelection()).trim();
           let extraHeaders = {};
           const rawHeaders = el('sandbox-extra-headers')?.value || '{}';
           if (rawHeaders.trim()) {
             extraHeaders = JSON.parse(rawHeaders);
           }
           if (!extraHeaders || typeof extraHeaders !== 'object' || Array.isArray(extraHeaders)) {
             throw new Error('Request Headers must be a JSON object.');
           }
           const templateHeaders = (tpl && tpl.headers && typeof tpl.headers === 'object' && !Array.isArray(tpl.headers)) ? tpl.headers : {};
           const headers = { ...templateHeaders, ...extraHeaders, ...sandboxBuildAuthHeader(authMode, authValue) };
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
        function toggleSandboxSection(toggleId, wrapId) {
          const link = el(toggleId);
          const wrap = el(wrapId);
          if (!link || !wrap) return;
          link.addEventListener('click', (evt) => {
            evt.preventDefault();
            const hidden = wrap.style.display === 'none';
            wrap.style.display = hidden ? 'block' : 'none';
            link.textContent = hidden ? 'hide' : 'show';
          });
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
           if (!el('sandbox-verb') || !el('sandbox-path')) return;
           sandboxRenderSelectors();
           if (!sandboxTemplateKey) sandboxApplyTemplate('request_passthrough');
           sandboxUpdateAuthValueVisibility();
           sandboxUpdateBaseUrlDisplay();
           sandboxSyncUrlFromSelection();
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
            setOutput('headers-output', 'Enrichments loaded.');
          } catch (e) {
            setOutput('headers-output', String(e.message || e));
          }
        }
        function addHeaderInputRow(name, value) {
          const body = el('headers-input-body');
          if (!body) return;
          const idx = body.children.length;
          const row = document.createElement('tr');
          row.innerHTML = ''
            + '<td style="padding:6px 8px;">'
            + '<input data-header-input="name" data-index="' + idx + '" value="' + htmlEscape(name || '') + '" placeholder="Header Key" style="width:100%;max-width:260px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
            + '</td>'
            + '<td style="padding:6px 8px;">'
            + '<input data-header-input="value" data-index="' + idx + '" value="' + htmlEscape(value || '') + '" placeholder="Header Value" style="width:100%;max-width:360px;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;" />'
            + '</td>'
            + '<td style="padding:6px 8px;text-align:right;">'
            + '<a href="#" class="remove-header-input" data-index="' + idx + '">Remove</a>'
            + '</td>';
          body.appendChild(row);
          updateHeaderInputAddButton();
        }
        function updateHeaderInputAddButton() {
          const body = el('headers-input-body');
          const btn = el('headers-add-row-btn');
          if (!body || !btn) return;
          let hasEmpty = false;
          body.querySelectorAll('tr').forEach((row) => {
            const name = String(row.querySelector('[data-header-input="name"]')?.value || '').trim();
            const value = String(row.querySelector('[data-header-input="value"]')?.value || '').trim();
            if (!name || !value) hasEmpty = true;
          });
          btn.disabled = hasEmpty;
          btn.style.opacity = hasEmpty ? '0.5' : '1';
          btn.style.cursor = hasEmpty ? 'not-allowed' : 'pointer';
        }
        async function headersSave() {
          try {
            const body = el('headers-input-body');
            if (!body) return;
            const rows = Array.from(body.querySelectorAll('tr'));
            if (!rows.length) {
              setOutput('headers-output', 'Add at least one header row.');
              return;
            }
            for (const row of rows) {
              const name = String(row.querySelector('[data-header-input="name"]')?.value || '').trim();
              const value = String(row.querySelector('[data-header-input="value"]')?.value || '').trim();
              if (!name || !value) {
                throw new Error('All header rows must include a key and value.');
              }
              await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(name), 'PUT', { value });
            }
            body.innerHTML = '';
            addHeaderInputRow('', '');
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
             const inboundHtml =
               '<div><b>Proxy key</b></div>'
               + '<div>Primary: ' + (proxy.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(proxy.proxy_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (proxy.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(proxy.proxy_secondary_key_created_at) + '</div>'
              + '<div>Expiry policy: ' + (proxy.expiry_seconds === null ? 'n/a' : String(proxy.expiry_seconds) + 's') + '</div>'
               + '<hr style="margin:10px 0;border:none;border-top:1px solid #eee;" />'
               + '<div><b>Target auth key</b></div>'
               + '<div>Primary: ' + (issuer.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(issuer.issuer_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (issuer.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(issuer.issuer_secondary_key_created_at) + '</div>'
              + '<div>Expiry policy: ' + (issuer.expiry_seconds === null ? 'n/a' : String(issuer.expiry_seconds) + 's') + '</div>';
            const adminHtml =
              '<div><b>Admin key</b></div>'
               + '<div>Primary: ' + (admin.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(admin.admin_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (admin.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(admin.admin_secondary_key_created_at) + '</div>'
              + '<div>Expiry policy: ' + (admin.expiry_seconds === null ? 'n/a' : String(admin.expiry_seconds) + 's') + '</div>';
             if (el('keys-status-inbound')) setHtml('keys-status-inbound', inboundHtml);
             if (el('keys-status-admin')) setHtml('keys-status-admin', adminHtml);
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
             setOutput('keys-output', await apiCall(ADMIN_ROOT + '/keys/issuer/rotate', 'POST'));
             await keysRefresh();
           }
           catch (e) { setOutput('keys-output', String(e.message || e)); }
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
           el('overview-refresh-btn')?.addEventListener('click', refreshOverview);
          el('debug-refresh-trace-link')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            debugLoadTrace();
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
            if (el('logging-secret-wrap')) el('logging-secret-wrap').style.display = enabled ? 'block' : 'none';
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
          el('footer-save-logging')?.addEventListener('click', loggingSecretSave);
          el('logging-secret-delete-btn')?.addEventListener('click', loggingSecretDelete);
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
           el('outbound-mode')?.addEventListener('change', () => {
             setOutboundMode(el('outbound-mode')?.value || 'autorotation');
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
           el('headers-add-row-btn')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             addHeaderInputRow('', '');
           });
           el('headers-input-body')?.addEventListener('input', updateHeaderInputAddButton);
           el('headers-input-body')?.addEventListener('click', (evt) => {
             const link = evt.target?.closest ? evt.target.closest('.remove-header-input') : null;
             if (!link) return;
             evt.preventDefault();
             link.closest('tr')?.remove();
             updateHeaderInputAddButton();
           });
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
            const addHeaderBtn = evt.target?.closest ? evt.target.closest('.rule-header-add-btn') : null;
            if (addHeaderBtn && addHeaderBtn.getAttribute('data-kind') === kind) {
              evt.preventDefault();
              const checkbox = document.querySelector('.rule-match-toggle[data-kind="' + kind + '"][data-index="' + addHeaderBtn.getAttribute('data-index') + '"][data-target^="rule-' + kind + '-"][data-target$="-headers"]');
              if (checkbox) checkbox.checked = true;
              const idx = Number(addHeaderBtn.getAttribute('data-index') || -1);
              if (idx >= 0) {
                addHeaderMatchRule(kind, idx);
                const panel = document.getElementById('rule-' + kind + '-' + idx + '-headers');
                if (panel) panel.style.display = 'block';
              }
              return;
            }
            const removeHeaderBtn = evt.target?.closest ? evt.target.closest('.rule-header-remove-btn') : null;
            if (removeHeaderBtn && removeHeaderBtn.getAttribute('data-kind') === kind) {
              evt.preventDefault();
              const idx = Number(removeHeaderBtn.getAttribute('data-index') || -1);
              const hIdx = Number(removeHeaderBtn.getAttribute('data-header-index') || -1);
              if (idx >= 0 && hIdx >= 0) removeHeaderMatchRule(kind, idx, hIdx);
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
          function updateHeaderAddButton(kind, idx) {
            const node = kind === 'outbound' ? el('outbound-rules-list') : el('inbound-rules-list');
            if (!node) return;
            const headerEnabled = node.querySelector('.rule-match-toggle[data-kind="' + kind + '"][data-index="' + idx + '"][data-target="rule-' + kind + '-' + idx + '-headers"]')?.checked;
            if (!headerEnabled) return;
            const headerNodes = node.querySelectorAll('[data-kind="' + kind + '"][data-field="headerName"][data-index="' + idx + '"]');
            let hasEmpty = false;
            headerNodes.forEach((input) => {
              const headerIndex = input.getAttribute('data-header-index');
              const name = String(input.value || '').trim();
              const valueInput = node.querySelector('[data-kind="' + kind + '"][data-field="headerValue"][data-index="' + idx + '"][data-header-index="' + headerIndex + '"]');
              const value = String(valueInput?.value || '').trim();
              if (!name || !value) hasEmpty = true;
            });
            const addBtn = node.querySelector('.rule-header-add-btn[data-kind="' + kind + '"][data-index="' + idx + '"]');
            if (addBtn) {
              addBtn.disabled = hasEmpty;
              addBtn.style.opacity = hasEmpty ? '0.5' : '1';
              addBtn.style.cursor = hasEmpty ? 'not-allowed' : 'pointer';
            }
          }
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
          el('keys-refresh-link-admin')?.addEventListener('click', (evt) => {
            evt.preventDefault();
            keysRefresh();
          });
          el('footer-save-inbound-auth')?.addEventListener('click', inboundAuthSave);
          el('footer-save-admin-auth')?.addEventListener('click', adminAuthSave);
           el('rotate-proxy-btn')?.addEventListener('click', rotateProxy);
           el('rotate-issuer-btn')?.addEventListener('click', rotateIssuer);
           el('rotate-admin-btn')?.addEventListener('click', rotateAdmin);
          el('sandbox-verb')?.addEventListener('change', sandboxApplyTemplateForSelection);
          el('sandbox-path')?.addEventListener('change', sandboxApplyTemplateForSelection);
          el('sandbox-auth-mode')?.addEventListener('change', () => {
            sandboxUpdateAuthValueVisibility();
            sandboxPreviewRequest();
          });
          el('sandbox-auth-value')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-url')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-extra-headers')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-body')?.addEventListener('input', sandboxPreviewRequest);
          el('sandbox-send-btn')?.addEventListener('click', sandboxSend);
          toggleSandboxSection('sandbox-url-toggle', 'sandbox-url-wrap');
          toggleSandboxSection('sandbox-headers-toggle', 'sandbox-headers-wrap');
          toggleSandboxSection('sandbox-body-toggle', 'sandbox-body-wrap');
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

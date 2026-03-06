         const ADMIN_ROOT = '/_apiproxy/admin';
         const ADMIN_ACCESS_TOKEN_STORAGE = 'apiproxy_admin_access_token_v1';
         let currentKey = '';
         let pendingDeleteHeaderName = '';
         let configValidateTimer = null;

         function el(id) { return document.getElementById(id); }
         function setOutput(id, data) {
           const node = el(id);
           if (!node) return;
           node.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
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
           const btn = el('config-save-btn');
           if (!btn) return;
           btn.disabled = !enabled;
           btn.style.opacity = enabled ? '1' : '0.5';
           btn.style.cursor = enabled ? 'pointer' : 'not-allowed';
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
            showWarning('Admin key is invalid or expired. Re-enter X-Admin-Key.');
         }
         async function apiCall(path, method, body, expectText) {
           if (!currentKey) {
             throw new Error('Login first.');
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
             if (name === 'key-rotation') keyRotationLoad();
             if (name === 'headers') headersList();
             if (name === 'keys') keysRefresh();
           }
           btns.forEach((btn) => {
             btn.style.padding = '8px 10px';
             btn.style.border = '1px solid #cbd5e1';
             btn.style.borderRadius = '8px';
             btn.style.background = '#fff';
             btn.style.textAlign = 'left';
             btn.style.cursor = 'pointer';
             btn.addEventListener('click', () => {
               const name = btn.getAttribute('data-tab');
               setActiveTab(name);
             });
           });
           setActiveTab('overview');
         }
         function formatOverviewStatus(version, debug, headers, targetHost) {
           const versionText = version?.data?.version || 'unknown';
           const debugData = debug?.data || {};
           const debugEnabled = !!debugData.enabled;
           const enrichedHeaders = Array.isArray(headers?.enriched_headers)
             ? headers.enriched_headers
             : (Array.isArray(headers?.data?.enriched_headers) ? headers.data.enriched_headers : []);
           return '<div><b>Build Version:</b> ' + versionText + '</div>'
             + '<div><b>Debug Enabled:</b> ' + (debugEnabled ? 'yes' : 'no') + '</div>'
             + '<div><b>Target URL:</b> ' + (targetHost || '(not set)') + '</div>'
             + '<div><b>Enrichments:</b> ' + (enrichedHeaders.length ? enrichedHeaders.join(', ') : '(none)') + '</div>';
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
             try {
               const res = await fetch(ADMIN_ROOT + '/config/validate', {
                 method: 'POST',
                 headers: { 'Authorization': 'Bearer ' + currentKey, 'Content-Type': 'text/yaml' },
                 body: yamlText,
               });
               const txt = await res.text();
               const parsed = JSON.parse(txt);
               if (res.ok) targetHost = parsed?.data?.config?.targetHost || '';
             } catch {}
             setHtml('overview-output', formatOverviewStatus(version, debug, headers, targetHost));
           } catch (e) {
             setOutput('overview-output', String(e.message || e));
           }
         }
         async function debugEnable() {
           try {
             setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug', 'PUT', { enabled: true }));
             await loadLoggingStatus();
           }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
         }
         async function debugDisable() {
           try {
             setOutput('logging-output', await apiCall(ADMIN_ROOT + '/debug', 'DELETE'));
             await loadLoggingStatus();
           }
           catch (e) { setOutput('debug-output', String(e.message || e)); }
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
             let endpointUrl = '(not set)';
             let endpointAuthHeader = '(not set)';
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
                 endpointUrl = cfg.url || '(not set)';
                 endpointAuthHeader = cfg.auth_header || '(not set)';
               }
             } catch {}
             if (el('logging-config-url')) el('logging-config-url').value = endpointUrl;
             if (el('logging-config-auth-header')) el('logging-config-auth-header').value = endpointAuthHeader;
             const d = debugStatus?.data || {};
             const statusHtml =
               '<div><b>Debug enabled:</b> ' + (d.enabled ? 'yes' : 'no') + '</div>'
               + '<div><b>Debug TTL remaining (seconds):</b> ' + Number(d.ttl_remaining_seconds || 0) + '</div>'
               + '<div><b>Logging secret set:</b> ' + (secretStatus?.data?.logging_secret_set ? 'yes' : 'no') + '</div>';
             setHtml('logging-status', statusHtml);
           } catch (e) {
             setOutput('logging-output', String(e.message || e));
           }
         }
         async function configLoad() {
           try {
             const text = await apiCall(ADMIN_ROOT + '/config', 'GET', undefined, true);
             if (el('config-yaml')) el('config-yaml').value = text;
             setConfigValidationError('');
             setConfigSaveEnabled(true);
             setOutput('config-output', 'Config reloaded from proxy.');
           } catch (e) {
              setOutput('config-output', String(e.message || e));
              setConfigSaveEnabled(false);
           }
         }
         async function configValidate(showOutput) {
           const yaml = el('config-yaml')?.value || '';
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
           const yaml = el('config-yaml')?.value || '';
           const valid = await configValidate(false);
           if (!valid) {
             setOutput('config-output', 'Save blocked: fix config validation errors first.');
             return;
           }
           try {
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
             const d = payload?.data || {};
             if (el('kr-enabled')) el('kr-enabled').checked = !!d.enabled;
             if (el('kr-strategy')) el('kr-strategy').value = d.strategy || 'json_ttl';
             if (el('kr-request-yaml')) el('kr-request-yaml').value = String(d.request_yaml || '');
             if (el('kr-key-path')) el('kr-key-path').value = String(d.key_path || '');
             if (el('kr-ttl-path')) el('kr-ttl-path').value = d.ttl_path == null ? '' : String(d.ttl_path);
             if (el('kr-ttl-unit')) el('kr-ttl-unit').value = d.ttl_unit || 'seconds';
             if (el('kr-expires-at-path')) el('kr-expires-at-path').value = d.expires_at_path == null ? '' : String(d.expires_at_path);
             if (el('kr-refresh-skew')) el('kr-refresh-skew').value = String(Number(d.refresh_skew_seconds || 0));
             if (el('kr-retry-on-401')) el('kr-retry-on-401').checked = !!d.retry_once_on_401;
             if (el('kr-proxy-expiry')) el('kr-proxy-expiry').value = d.proxy_expiry_seconds == null ? 'null' : String(d.proxy_expiry_seconds);
             if (el('kr-issuer-expiry')) el('kr-issuer-expiry').value = d.issuer_expiry_seconds == null ? 'null' : String(d.issuer_expiry_seconds);
             if (el('kr-admin-expiry')) el('kr-admin-expiry').value = d.admin_expiry_seconds == null ? 'null' : String(d.admin_expiry_seconds);
             setOutput('kr-output', 'Key rotation config loaded.');
           } catch (e) {
             setOutput('kr-output', String(e.message || e));
           }
         }
         async function keyRotationSave() {
           try {
             const payload = {
               enabled: !!el('kr-enabled')?.checked,
               strategy: (el('kr-strategy')?.value || 'json_ttl'),
               request_yaml: el('kr-request-yaml')?.value || '',
               key_path: el('kr-key-path')?.value || '',
               ttl_path: el('kr-ttl-path')?.value || null,
               ttl_unit: el('kr-ttl-unit')?.value || 'seconds',
               expires_at_path: el('kr-expires-at-path')?.value || null,
               refresh_skew_seconds: Number(el('kr-refresh-skew')?.value || 0),
               retry_once_on_401: !!el('kr-retry-on-401')?.checked,
               proxy_expiry_seconds: normalizeNullableIntegerInput(el('kr-proxy-expiry')?.value),
               issuer_expiry_seconds: normalizeNullableIntegerInput(el('kr-issuer-expiry')?.value),
               admin_expiry_seconds: normalizeNullableIntegerInput(el('kr-admin-expiry')?.value),
             };
             const out = await apiCall(ADMIN_ROOT + '/key-rotation-config', 'PUT', payload);
             setOutput('kr-output', out);
           } catch (e) {
             setOutput('kr-output', String(e.message || e));
           }
         }
         async function headersList() {
           try {
             const payload = await apiCall(ADMIN_ROOT + '/headers', 'GET');
             const names = Array.isArray(payload?.enriched_headers) ? payload.enriched_headers : [];
             if (!names.length) {
               setHtml('headers-list', '<div>(none)</div>');
             } else {
               const rows = names.map((name) =>
                 '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #eee;">'
                 + '<span>' + name + '</span>'
                 + '<button type="button" class="delete-header-btn" data-name="' + name + '">Delete</button>'
                 + '</div>'
               );
               setHtml('headers-list', rows.join(''));
             }
             setOutput('headers-output', 'Enrichments loaded.');
           } catch (e) {
             setOutput('headers-output', String(e.message || e));
           }
         }
         async function headersSave() {
           const name = (el('header-name')?.value || '').trim();
           const value = el('header-value')?.value || '';
           try {
             await apiCall(ADMIN_ROOT + '/headers/' + encodeURIComponent(name), 'PUT', { value });
             if (el('header-name')) el('header-name').value = '';
             if (el('header-value')) el('header-value').value = '';
             setOutput('headers-output', 'Enrichment added.');
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
         function toggleHeaderValueVisibility() {
           const field = el('header-value');
           const btn = el('header-value-toggle-btn');
           if (!field || !btn) return;
           const hidden = field.type === 'password';
           field.type = hidden ? 'text' : 'password';
           btn.textContent = hidden ? 'hide' : 'show';
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
             const html =
               '<div><b>Proxy key</b></div>'
               + '<div>Primary: ' + (proxy.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(proxy.proxy_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (proxy.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(proxy.proxy_secondary_key_created_at) + '</div>'
               + '<div>Expiry policy: ' + (proxy.expiry_seconds === null ? 'null (long-lived)' : String(proxy.expiry_seconds) + 's') + '</div>'
               + '<hr style="margin:10px 0;border:none;border-top:1px solid #eee;" />'
               + '<div><b>Target auth key</b></div>'
               + '<div>Primary: ' + (issuer.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(issuer.issuer_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (issuer.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(issuer.issuer_secondary_key_created_at) + '</div>'
               + '<div>Expiry policy: ' + (issuer.expiry_seconds === null ? 'null (long-lived)' : String(issuer.expiry_seconds) + 's') + '</div>'
               + '<hr style="margin:10px 0;border:none;border-top:1px solid #eee;" />'
               + '<div><b>Admin key</b></div>'
               + '<div>Primary: ' + (admin.primary_active ? 'active' : 'missing') + '</div>'
               + '<div>Primary created: ' + formatCreatedAt(admin.admin_primary_key_created_at) + '</div>'
               + '<div>Secondary overlap key: ' + (admin.secondary_active ? 'active' : 'inactive') + '</div>'
               + '<div>Secondary created: ' + formatCreatedAt(admin.admin_secondary_key_created_at) + '</div>'
               + '<div>Expiry policy: ' + (admin.expiry_seconds === null ? 'null (long-lived)' : String(admin.expiry_seconds) + 's') + '</div>';
             setHtml('keys-status', html);
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
             await keysRefresh();
             setCurrentKey('');
             showWarning('Admin key rotated. Re-enter the new admin key from response.');
           } catch (e) {
             setOutput('keys-output', String(e.message || e));
           }
         }

         function bind() {
           attachTabs();
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
                 await headersList();
                 await keysRefresh();
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
           el('logging-open-config-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             document.querySelector('.tab-btn[data-tab="config"]')?.click();
           });
           el('debug-enable-btn')?.addEventListener('click', debugEnable);
           el('debug-disable-btn')?.addEventListener('click', debugDisable);
           el('logging-secret-save-btn')?.addEventListener('click', loggingSecretSave);
           el('logging-secret-delete-btn')?.addEventListener('click', loggingSecretDelete);
           el('config-reload-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             configLoad();
           });
           el('config-test-rule-link')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             configTestRule();
           });
           el('config-save-btn')?.addEventListener('click', configSave);
           el('kr-save-btn')?.addEventListener('click', keyRotationSave);
           el('kr-reload-btn')?.addEventListener('click', keyRotationLoad);
           el('config-yaml')?.addEventListener('input', () => {
             setConfigSaveEnabled(false);
             if (configValidateTimer) clearTimeout(configValidateTimer);
             configValidateTimer = setTimeout(() => { configValidate(false); }, 350);
           });
           el('config-yaml')?.addEventListener('blur', () => configValidate(true));
           el('headers-save-btn')?.addEventListener('click', headersSave);
           el('header-value-toggle-btn')?.addEventListener('click', (evt) => {
             evt.preventDefault();
             toggleHeaderValueVisibility();
           });
           el('headers-list')?.addEventListener('click', (evt) => {
             const target = evt.target?.closest ? evt.target.closest('.delete-header-btn') : null;
             if (!target) return;
             const name = target.getAttribute('data-name') || '';
             promptDeleteHeader(name);
           });
           el('delete-header-cancel-btn')?.addEventListener('click', () => {
             pendingDeleteHeaderName = '';
             el('delete-header-modal')?.close();
           });
           el('delete-header-confirm-btn')?.addEventListener('click', headersDeleteConfirmed);
           el('keys-refresh-btn')?.addEventListener('click', keysRefresh);
           el('rotate-proxy-btn')?.addEventListener('click', rotateProxy);
           el('rotate-issuer-btn')?.addEventListener('click', rotateIssuer);
           el('rotate-admin-btn')?.addEventListener('click', rotateAdmin);
           try {
             const token = sessionStorage.getItem(ADMIN_ACCESS_TOKEN_STORAGE) || '';
             if (token) {
               setCurrentKey(token);
               refreshOverview();
               debugLoadTrace();
               loadLoggingStatus();
               configLoad();
               keyRotationLoad();
               headersList();
               keysRefresh();
             }
           } catch {}
         }
         bind();
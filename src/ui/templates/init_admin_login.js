async function initAdminLogin() {
  const input = document.getElementById('init-admin-key');
  const msg = document.getElementById('init-admin-login-msg');
  const key = (input && input.value || '').trim();
  if (!key) {
    if (msg) msg.textContent = 'Enter your Admin API key first.';
    return;
  }
  try {
    const res = await fetch('{{admin_root}}/access-token', {
      method: 'POST',
      headers: { 'X-Admin-Key': key },
    });
    const text = await res.text();
    let payload = null;
    try { payload = JSON.parse(text); } catch {}
    if (!res.ok || !payload?.data?.access_token) {
      if (msg) msg.textContent = 'Login failed. Check your admin key and try again.';
      return;
    }
    try { sessionStorage.setItem('apiproxy_admin_access_token_v1', payload.data.access_token); } catch {}
    window.location.href = '{{admin_root}}';
  } catch {
    if (msg) msg.textContent = 'Login failed. Try again.';
  }
}

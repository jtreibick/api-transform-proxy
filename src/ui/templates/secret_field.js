function toggleSecret(id) {
  const input = document.getElementById(id);
  const btn = document.querySelector('[data-toggle-for="' + id + '"]');
  if (!input || !btn || btn.disabled) return;
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  btn.textContent = isHidden ? 'Hide' : 'Show';
}

async function copySecret(id) {
  const input = document.getElementById(id);
  const btn = document.querySelector('[data-copy-for="' + id + '"]');
  if (!input || !btn || btn.disabled || !input.value) return;
  try {
    await navigator.clipboard.writeText(input.value);
    const old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = old; }, 1200);
  } catch {}
}

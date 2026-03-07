import pageTemplate from "./ui/templates/page.html";
import onboardingHeaderTemplate from "./ui/templates/onboarding_header.html";
import adminLoginOptionsTemplate from "./ui/templates/admin_login_options.html";
import adminPageTemplate from "./ui/templates/admin_page.html";
import initAdminLoginJs from "./ui/templates/init_admin_login.js";
import secretFieldTemplate from "./ui/templates/secret_field.html";
import secretFieldJs from "./ui/templates/secret_field.js";
import adminPageJs from "./ui/templates/admin_page.js";

const templates = {
  page: pageTemplate,
  onboarding_header: onboardingHeaderTemplate,
  admin_login_options: adminLoginOptionsTemplate,
  admin_page: adminPageTemplate,
  init_admin_login_js: initAdminLoginJs,
  secret_field: secretFieldTemplate,
  secret_field_js: secretFieldJs,
  admin_page_js: adminPageJs,
};

export const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 72 72">
  <rect width="72" height="72" rx="16" fill="#0f172a"/>
  <path d="M24 15L11 24v24l13 9" fill="none" stroke="#e2e8f0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M48 15l13 9v24l-13 9" fill="none" stroke="#e2e8f0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M39 9L25 36h8l-3 27 16-31h-9z" fill="#22d3ee"/>
</svg>`;

export const FAVICON_DATA_URL = `data:image/svg+xml,${encodeURIComponent(FAVICON_SVG)}`;

export function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function capitalize(s) {
  const v = String(s || "");
  if (!v) return v;
  return v.charAt(0).toUpperCase() + v.slice(1);
}

function renderTemplate(name, vars = {}) {
  const src = templates[name] || "";
  return src.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, key) => (key in vars ? String(vars[key]) : ""));
}

export function htmlPage(title, bodyHtml) {
  const safeTitle = escapeHtml(title || "");
  return renderTemplate("page", {
    title: safeTitle,
    favicon_data_url: FAVICON_DATA_URL,
    heading_text: safeTitle,
    heading_style: safeTitle ? "" : "display:none;",
    body_html: bodyHtml || "",
  });
}

export function renderOnboardingHeader(proxyName = "") {
  const name = String(proxyName || "").trim();
  return renderTemplate("onboarding_header", {
    favicon_data_url: FAVICON_DATA_URL,
    proxy_name: escapeHtml(name),
    proxy_name_style: name ? "" : "display:none;",
  });
}

export function renderAdminLoginOptions(docsUrl) {
  return renderTemplate("admin_login_options", {
    docs_url: escapeHtml(docsUrl || ""),
  });
}

export function renderInitAdminLoginScript(adminRoot) {
  const js = renderTemplate("init_admin_login_js", {
    admin_root: String(adminRoot || ""),
  });
  return `<script>\n${js}\n</script>`;
}

export function renderSecretField(label, value, id, note = "", actionsEnabled = true) {
  const disabledAttr = actionsEnabled ? "" : " disabled";
  const buttonStyle = actionsEnabled
    ? "padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;cursor:pointer;"
    : "padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;background:#f3f4f6;color:#9ca3af;cursor:not-allowed;opacity:0.85;";
  const noteBlock = note ? `<div style=\"margin-top:6px;color:#6b7280;font-size:12px;\">${String(note)}</div>` : "";
  return renderTemplate("secret_field", {
    label: escapeHtml(label),
    value: escapeHtml(value),
    id: escapeHtml(id),
    button_style: buttonStyle,
    disabled_attr: disabledAttr,
    note_block: noteBlock,
  });
}

export function renderSecretFieldScript() {
  const js = templates.secret_field_js || "";
  return `<script>\n${js}\n</script>`;
}

export function renderAdminPage() {
  const bodyHtml = renderTemplate("admin_page", {
    favicon_data_url: FAVICON_DATA_URL,
  });
  return new Response(
    htmlPage("", bodyHtml),
    { headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

export function renderAdminPageScript() {
  return templates.admin_page_js || "";
}

const INCLUDE_SELECTOR = "template[data-include]";
const APP_SCRIPTS = ["./index.i18n.js", "./index.core.js", "./index.events.js"];

function failPage(error) {
  const message = error instanceof Error ? error.message : String(error || "unknown error");
  document.body.innerHTML = "";
  const pre = document.createElement("pre");
  pre.style.padding = "16px";
  pre.style.margin = "0";
  pre.textContent = `Failed to load UI assets: ${message}`;
  document.body.appendChild(pre);
}

async function fetchInclude(path) {
  const target = String(path || "").trim();
  if (!target) {
    throw new Error("empty include path");
  }
  const res = await fetch(target, { cache: "no-cache" });
  if (!res.ok) {
    throw new Error(`${target} -> HTTP ${res.status}`);
  }
  return await res.text();
}

function mountInclude(slot, html) {
  const wrapper = document.createElement("template");
  wrapper.innerHTML = html.trim();
  slot.replaceWith(wrapper.content);
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = false;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`script load failed: ${src}`));
    document.body.appendChild(script);
  });
}

async function composePage() {
  const slots = [...document.querySelectorAll(INCLUDE_SELECTOR)];
  const fragments = await Promise.all(slots.map((slot) => fetchInclude(slot.dataset.include)));
  slots.forEach((slot, idx) => mountInclude(slot, fragments[idx]));
  for (const src of APP_SCRIPTS) {
    await loadScript(src);
  }
}

composePage().catch((error) => {
  console.error(error);
  failPage(error);
});

// Content script: when "check on click" is enabled, intercept link clicks,
// detonate the URL via the background worker, and show a verdict/block overlay
// before navigation. The overlay lives in a shadow root so page CSS can't touch
// it, and all injected text uses textContent (no markup injection).

(() => {
  let checkMode = "manual";
  const approved = new Set(); // URLs the user chose to proceed to

  chrome.storage.sync.get({ checkMode: "manual" }, (o) => {
    checkMode = o.checkMode || "manual";
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.checkMode) checkMode = changes.checkMode.newValue;
  });

  const clickActive = () => checkMode === "click" || checkMode === "both";

  document.addEventListener("click", onClick, true);

  function onClick(e) {
    if (!clickActive()) return;
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a) return;

    let url;
    try {
      url = new URL(a.href, location.href);
    } catch {
      return;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return;
    // ignore in-page anchors (same doc, different #fragment)
    if (url.href.split("#")[0] === location.href.split("#")[0]) return;
    if (approved.has(url.href)) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    handle(url.href, a.target === "_blank");
  }

  async function handle(url, newTab) {
    const ov = Overlay.open();
    ov.checking(url);

    const resp = await sendMessage({ type: "CHECK_URL", url });

    if (resp && resp.ok) {
      const verdict = resp.data.verdict || "safe";
      if (verdict === "safe") {
        ov.close();
        proceed(url, newTab);
        return;
      }
      const choice = await ov.verdict(resp.data);
      ov.close();
      if (choice === "proceed") proceed(url, newTab);
    } else {
      const choice = await ov.unavailable(resp ? resp.error : "No response from extension.");
      ov.close();
      if (choice === "proceed") proceed(url, newTab);
    }
  }

  function proceed(url, newTab) {
    approved.add(url);
    if (newTab) window.open(url, "_blank", "noopener");
    else window.location.assign(url);
  }

  function sendMessage(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (resp) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
          } else {
            resolve(resp || { ok: false, error: "No response from extension." });
          }
        });
      } catch (err) {
        resolve({ ok: false, error: String((err && err.message) || err) });
      }
    });
  }

  function hostOf(u) {
    try {
      return new URL(u).hostname.replace(/^www\./, "");
    } catch {
      return u || "";
    }
  }

  // ---------- shadow-DOM overlay ----------
  const Overlay = (() => {
    let hostEl = null;
    let shadow = null;
    let pending = null; // resolver for the current choice promise

    const STYLE = `
      :host { all: initial; }
      .scrim {
        position: fixed; inset: 0; z-index: 2147483647;
        display: grid; place-items: center;
        background: rgba(6, 9, 13, 0.72); backdrop-filter: blur(3px);
        font-family: system-ui, "Segoe UI", sans-serif;
      }
      .card {
        width: min(420px, 92vw); background: #141b24; color: #e8edf2;
        border: 1px solid #29333f; border-radius: 8px; overflow: hidden;
        box-shadow: 0 30px 70px -20px rgba(0,0,0,.8);
      }
      .bar { height: 6px; }
      .bar.safe { background: #37d399; } .bar.suspicious { background: #ffa62b; }
      .bar.dangerous { background: #ff5765; } .bar.checking { background: #58d7e6; }
      .bar.error { background: #93a0ae; }
      .pad { padding: 18px 18px 16px; }
      .eyebrow { font: 600 11px/1 ui-monospace, monospace; letter-spacing: .18em;
        text-transform: uppercase; color: #5e6b79; margin: 0 0 8px; }
      h2 { margin: 0 0 4px; font-size: 19px; }
      h2.safe { color: #37d399; } h2.suspicious { color: #ffa62b; }
      h2.dangerous { color: #ff5765; } h2.error { color: #cfd8e2; }
      .host { font: 13px ui-monospace, monospace; color: #93a0ae; word-break: break-all; margin: 0 0 12px; }
      .shot { width: 100%; height: 130px; object-fit: cover; object-position: top center;
        border-radius: 5px; border: 1px solid #29333f; margin: 0 0 12px; }
      ul { list-style: none; margin: 0 0 14px; padding: 0; display: flex; flex-direction: column; gap: 6px; }
      li { font-size: 13px; background: #0b0f14; border: 1px solid #29333f;
        border-left: 3px solid #58d7e6; border-radius: 4px; padding: 8px 10px; }
      li.hi { border-left-color: #ff5765; } li.mid { border-left-color: #ffa62b; }
      .actions { display: flex; gap: 8px; }
      button { flex: 1; font: 600 13px system-ui; letter-spacing: .04em; padding: 11px;
        border-radius: 5px; border: 1px solid transparent; cursor: pointer; }
      .cancel { background: #58d7e6; color: #06222a; }
      .proceed { background: transparent; color: #93a0ae; border-color: #3a4754; }
      .proceed:hover { color: #e8edf2; }
      .spinner { display: flex; align-items: center; gap: 10px; font: 13px ui-monospace, monospace; color: #58d7e6; }
      .dot { width: 10px; height: 10px; border-radius: 50%; background: #58d7e6;
        animation: p 1s ease-in-out infinite; }
      @keyframes p { 0%,100%{opacity:1} 50%{opacity:.2} }
      @media (prefers-reduced-motion: reduce){ .dot{animation:none} }
    `;

    function ensure() {
      if (hostEl) return;
      hostEl = document.createElement("div");
      hostEl.id = "sandboxed-overlay-host";
      shadow = hostEl.attachShadow({ mode: "open" });
      document.documentElement.appendChild(hostEl);
    }

    function el(tag, opts = {}, kids = []) {
      const n = document.createElement(tag);
      if (opts.class) n.className = opts.class;
      if (opts.text != null) n.textContent = opts.text;
      if (opts.attrs) for (const k in opts.attrs) n.setAttribute(k, opts.attrs[k]);
      for (const kid of kids) if (kid) n.appendChild(kid);
      return n;
    }

    function paint(barClass, body) {
      ensure();
      const style = document.createElement("style");
      style.textContent = STYLE;
      const card = el("div", { class: "card" }, [
        el("div", { class: "bar " + barClass }),
        el("div", { class: "pad" }, body),
      ]);
      const scrim = el("div", { class: "scrim" }, [card]);
      shadow.replaceChildren(style, scrim);
      hostEl.style.display = "block";
    }

    function resolveWith(choice) {
      const r = pending;
      pending = null;
      if (r) r(choice);
    }

    return {
      open() {
        return this;
      },
      checking(url) {
        paint("checking", [
          el("p", { class: "eyebrow", text: "Sandboxed" }),
          el("div", { class: "spinner" }, [
            el("span", { class: "dot" }),
            el("span", { text: "Checking " + hostOf(url) + "…" }),
          ]),
        ]);
      },
      verdict(data) {
        const verdict = data.verdict || "suspicious";
        const dangerous = verdict === "dangerous";
        const body = [
          el("p", { class: "eyebrow", text: "Sandboxed verdict" }),
          el("h2", {
            class: verdict,
            text: (dangerous ? "Dangerous link blocked" : "Suspicious link") +
              " · " + (data.score ?? 0),
          }),
          el("p", { class: "host", text: data.finalHost || hostOf(data.finalUrl) || "" }),
        ];
        if (data.screenshotBase64) {
          body.push(
            el("img", {
              class: "shot",
              attrs: { src: "data:image/jpeg;base64," + data.screenshotBase64, alt: "" },
            })
          );
        }
        const reasons = (data.reasons || []).slice(0, 3);
        if (reasons.length) {
          body.push(
            el(
              "ul",
              {},
              reasons.map((r) =>
                el("li", { class: r.points >= 30 ? "hi" : r.points >= 12 ? "mid" : "", text: r.reason })
              )
            )
          );
        }
        const cancelBtn = el("button", {
          class: "cancel",
          text: dangerous ? "Go back (safe)" : "Cancel",
        });
        const proceedBtn = el("button", {
          class: "proceed",
          text: dangerous ? "Proceed anyway" : "Proceed",
        });
        cancelBtn.addEventListener("click", () => resolveWith("cancel"));
        proceedBtn.addEventListener("click", () => resolveWith("proceed"));
        body.push(el("div", { class: "actions" }, [cancelBtn, proceedBtn]));

        paint(verdict, body);
        return new Promise((res) => (pending = res));
      },
      unavailable(message) {
        const cancelBtn = el("button", { class: "cancel", text: "Cancel" });
        const proceedBtn = el("button", { class: "proceed", text: "Proceed anyway" });
        cancelBtn.addEventListener("click", () => resolveWith("cancel"));
        proceedBtn.addEventListener("click", () => resolveWith("proceed"));
        paint("error", [
          el("p", { class: "eyebrow", text: "Sandboxed" }),
          el("h2", { class: "error", text: "Backend unavailable" }),
          el("p", { class: "host", text: message || "Couldn't reach the detonation engine." }),
          el("div", { class: "actions" }, [cancelBtn, proceedBtn]),
        ]);
        return new Promise((res) => (pending = res));
      },
      close() {
        if (hostEl) {
          hostEl.style.display = "none";
          shadow.replaceChildren();
        }
        resolveWith("cancel");
      },
    };
  })();
})();

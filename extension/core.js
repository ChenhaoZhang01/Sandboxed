// Shared logic for the popup and the result window. Exposed as window.SBX.
// All result rendering builds DOM with textContent (no innerHTML) so untrusted
// page content from the detonated site can never inject markup here.
const SBX = (() => {
  const DEFAULT_API = "http://localhost:8787";

  function getApiBase() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ apiBase: DEFAULT_API }, (o) =>
        resolve((o.apiBase || DEFAULT_API).replace(/\/$/, ""))
      );
    });
  }

  function setApiBase(value) {
    return new Promise((resolve) =>
      chrome.storage.sync.set({ apiBase: (value || "").trim() }, resolve)
    );
  }

  async function detonate(url) {
    const base = await getApiBase();
    const res = await fetch(base + "/detonate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Detonation failed (HTTP ${res.status})`);
    return data;
  }

  // --- small DOM helper ---
  function el(tag, opts = {}, kids = []) {
    const n = document.createElement(tag);
    if (opts.class) n.className = opts.class;
    if (opts.text != null) n.textContent = opts.text;
    if (opts.data) for (const k in opts.data) n.dataset[k] = opts.data[k];
    if (opts.attrs) for (const k in opts.attrs) n.setAttribute(k, opts.attrs[k]);
    for (const kid of kids) if (kid) n.appendChild(kid);
    return n;
  }

  function hostOf(u) {
    try {
      return new URL(u).hostname.replace(/^www\./, "");
    } catch {
      return u || "";
    }
  }
  function pathOf(u) {
    try {
      const x = new URL(u);
      return (x.pathname + x.search).replace(/^\/$/, "");
    } catch {
      return "";
    }
  }
  function formatAge(age) {
    if (!age || typeof age.ageDays !== "number") return "unknown";
    const d = age.ageDays;
    if (d < 31) return d + " days · NEW";
    if (d < 365) return Math.round(d / 30) + " months";
    return (d / 365).toFixed(1) + " years";
  }

  function renderLoading(root, url) {
    root.replaceChildren(
      el("div", { class: "chamber" }, [
        el("div", { class: "grid-bg" }),
        el("div", { class: "spinner" }, [
          el("p", { text: "Detonating " + hostOf(url) + "…" }),
          el("div", { class: "bar" }, [el("span")]),
        ]),
      ])
    );
  }

  function renderError(root, msg) {
    root.replaceChildren(el("div", { class: "error-box", text: msg }));
  }

  function renderResult(root, d) {
    const verdict = d.verdict || "safe";

    // chamber: screenshot + glass + verdict stamp
    const chamberKids = [el("div", { class: "grid-bg" })];
    if (d.screenshotBase64) {
      chamberKids.push(
        el("img", {
          class: "shot",
          attrs: { src: "data:image/jpeg;base64," + d.screenshotBase64, alt: "Detonated page" },
        })
      );
      chamberKids.push(el("div", { class: "glass" }));
    }
    const stamp = el("div", { class: "stamp stamp-in", data: { verdict } });
    stamp.appendChild(document.createTextNode(verdict.toUpperCase() + " "));
    stamp.appendChild(el("span", { class: "score", text: "· " + (d.score ?? 0) }));
    chamberKids.push(stamp);
    const chamber = el("div", { class: "chamber" }, chamberKids);

    // meta grid
    const meta = (k, v) =>
      el("div", { class: "meta" }, [
        el("div", { class: "k", text: k }),
        el("div", { class: "v", text: v }),
      ]);
    const grid = el("div", { class: "readout-grid" }, [
      meta("Final destination", d.finalHost || hostOf(d.finalUrl) || "—"),
      meta("Domain age", formatAge(d.intel && d.intel.domainAge)),
      meta(
        "Redirects",
        (d.redirectCount ?? 0) + (d.redirectCount === 1 ? " hop" : " hops")
      ),
      meta("Page title", d.title || "—"),
    ]);

    // trajectory
    const traj = el("ul", { class: "traj" });
    const chain = d.redirectChain || [];
    if (!chain.length) {
      traj.appendChild(el("li", { class: "final", text: "(no navigation captured)" }));
    } else {
      chain.forEach((u, i) => {
        const li = el("li", { class: i === chain.length - 1 ? "final" : "" }, [
          el("span", { class: "host", text: hostOf(u) }),
        ]);
        const p = pathOf(u);
        if (p) li.appendChild(el("span", { text: " " + p, attrs: { style: "color:var(--ink-faint)" } }));
        traj.appendChild(li);
      });
    }

    // reasons
    const reasons = el("ul", { class: "reasons" });
    const list = d.reasons || [];
    if (!list.length) {
      reasons.appendChild(
        el("li", {}, [
          el("div", {
            class: "empty-reasons",
            text: "No threat signals detected — nothing suspicious in the chamber.",
          }),
        ])
      );
    } else {
      list.forEach((r) => {
        const sev = r.points >= 30 ? "sev-hi" : r.points >= 12 ? "sev-mid" : "sev-lo";
        reasons.appendChild(
          el("li", { class: "reason " + sev }, [
            el("span", { class: "pts mono", text: "+" + r.points }),
            el("span", { text: r.reason }),
          ])
        );
      });
    }

    root.replaceChildren(
      chamber,
      el("div", { class: "readout" }, [
        grid,
        el("div", { class: "section-label", text: "Trajectory" }),
        traj,
        el("div", { class: "section-label", text: "Why" }),
        reasons,
      ])
    );
  }

  return { DEFAULT_API, getApiBase, setApiBase, detonate, renderLoading, renderError, renderResult };
})();

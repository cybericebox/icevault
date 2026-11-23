"use strict";
// The stand-in of the Wails bridge for the browser test harness (harness.go; development only, never in a release). window.go.desktop.App.<Method>(...args)
// is a POST to /harness/call that the harness runs on the real internal/desktop App; window.runtime.EventsOn gets the program's events from the
// server-sent events of /harness/events. The page and adapter.js are the window's own, unchanged.
(function () {
  async function call(method, args) {
    const r = await fetch("/harness/call", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ method, args }) });
    if (!r.ok) throw new Error("harness: " + method + " answered " + r.status);
    return r.json();
  }
  const app = new Proxy({}, { get: (_, name) => (typeof name === "string" ? (...args) => call(name, args) : undefined) });
  window.go = { desktop: { App: app } };
  const handlers = {};
  let stream = null;
  window.runtime = {
    EventsOn(name, fn) {
      (handlers[name] = handlers[name] || []).push(fn);
      if (!stream) {
        stream = new EventSource("/harness/events");
        stream.onmessage = (e) => {
          let m;
          try { m = JSON.parse(e.data); } catch (_) { return; }
          (handlers[m.event] || []).forEach((f) => f(m.data));
        };
      }
      return () => { handlers[name] = (handlers[name] || []).filter((f) => f !== fn); };
    },
  };
})();

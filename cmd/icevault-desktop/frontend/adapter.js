"use strict";
// The bridge of the window: the page's api(path, body) calls become calls of the bound Go methods (internal/desktop App). It answers the same
// {status, data} the page logic got from fetch. No network, no storage, no value kept here.
(function () {
  const GETS = new Set(["nav", "item", "compare", "references", "pull-candidates", "shared", "visibility", "preview-value", "migrate-plan"]);
  function bridge() {
    const a = window.go && window.go.desktop && window.go.desktop.App;
    if (!a) throw new Error("the window bridge is not available");
    return a;
  }
  function split(path) {
    const i = path.indexOf("?");
    const op = (i < 0 ? path : path.slice(0, i)).replace(/^\/api\//, "");
    const args = {};
    if (i >= 0) new URLSearchParams(path.slice(i + 1)).forEach((v, k) => { args[k] = v; });
    return { op, args };
  }
  window.icevaultApi = async function (path, body) {
    const { op, args } = split(path);
    const b = body || {}, app = bridge();
    switch (op) {
      case "status": return app.Status();
      case "ping": return app.Ping(!!b.active);
      case "close": return app.Close();
      case "lock": return app.Lock();
      case "mode": return app.SetMode(String(b.mode || ""));
      case "unlock": return app.Unlock(String(b.method || ""), typeof b.password === "string" ? b.password : "");
      case "reveal": return app.Reveal(b);
      case "cli": return app.CLIStatus();
      case "cli-install": return app.CLIInstall(!!b.replace);
      case "refresh": return app.Refresh();
      case "vaults": return app.ListVaults();
      case "vault-select": return app.SelectVault(String(b.path || ""));
      case "vault-open": return app.OpenVault(String(b.title || ""));
      case "vault-root": return app.ChooseRoot(String(b.title || ""));
      case "vault-forget": return app.ForgetVault(String(b.path || ""));
      case "vault-new-noproject": return app.NewVaultNoProject();
      case "vault-no-project": return app.UseWithoutProject();
      case "vault-new-project": return app.NewVaultProject(String(b.title || ""));
      case "vault-new-place": return app.NewVaultPlace(String(b.title || ""));
      case "vault-new-strength": return app.PasswordStrength(typeof b.password === "string" ? b.password : "");
      case "vault-new-generate": return app.GeneratePassword();
      case "vault-new-create": return app.CreateVault(typeof b.password === "string" ? b.password : "", typeof b.confirm === "string" ? b.confirm : "", !!b.touchid);
      case "vault-change-info": return app.ChangePasswordInfo();
      case "vault-change": return app.ChangePassword(typeof b.current === "string" ? b.current : "", typeof b.password === "string" ? b.password : "", typeof b.confirm === "string" ? b.confirm : "", !!b.touchid, !!b.refresh);
      case "kit-save": return app.SaveRecoveryKit(String(b.title || ""), String(b.template || ""));
      case "kit-discard": return app.DiscardRecoveryKit();
      case "kit-held": return app.KitHeld();
      case "project-choose": return app.ChooseProject(String(b.title || ""));
      case "agent-pending": return app.AgentPending();
      case "agent-decide": return app.AgentDecide(String(b.id || ""), !!b.allow);
      case "agent-journal": return app.AgentJournal();
      case "update": return app.UpdateStatus();
      case "update-check": return app.UpdateCheck();
      case "update-fetch": return app.UpdateFetch();
      case "update-apply": return app.UpdateApply();
      case "update-auto": return app.UpdateAuto(!!b.on);
      case "update-release": return app.UpdateRelease();
    }
    if (GETS.has(op)) return app.Read(op, body === undefined ? args : b);
    return app.Write(op, b);
  };
  // the clipboard is the system's, cleared by the program after a while; copySecret never brings the value to the page
  window.icevaultCopyText = (text) => bridge().CopyText(String(text));
  window.icevaultCopySecret = (ref) => bridge().CopySecret(ref);
  // an event of the program (vault-changed: another writer saved the vault and it was read again); false when the shell has no event runtime
  window.icevaultOn = (name, fn) => { const r = window.runtime; if (!r || typeof r.EventsOn !== "function") return false; r.EventsOn(name, fn); return true; };
})();

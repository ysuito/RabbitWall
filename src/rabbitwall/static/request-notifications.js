"use strict";
(function(root) {
  class RequestNotifications {
    constructor() { this.seen = new Set(); }
    update(requests) {
      const pending = requests.filter(item => item.status === "pending");
      const added = pending.filter(item => !this.seen.has(item.id));
      for (const item of requests) this.seen.add(item.id);
      // Bound long-lived tabs without forgetting any currently retained request.
      if (this.seen.size > 512) this.seen = new Set([...this.seen].slice(-256).concat(requests.map(item=>item.id)));
      return {pending, added};
    }
  }
  class RequestSound {
    constructor(factory, storage = () => null) {
      this.factory = factory;
      this.storage = storage;
      this.context = null;
      this.enabled = false;
      try { this.enabled = this.storage()?.getItem("rabbitwall-request-sound") === "on"; } catch (_) {}
    }
    get ready() { return this.context?.state === "running"; }
    save() {
      try { this.storage()?.setItem("rabbitwall-request-sound", this.enabled ? "on" : "off"); } catch (_) {}
    }
    async prepare(confirm = false) {
      if (!this.context) this.context = this.factory();
      await this.context.resume();
      if (!this.ready) throw new Error("Audio is suspended");
      if (confirm && this.enabled) this.play();
    }
    async enable() {
      this.enabled = true;
      this.save();
      await this.prepare(true);
    }
    async restore() {
      if (this.enabled) await this.prepare();
    }
    disable() { this.enabled = false; this.save(); }
    play() {
      if (!this.enabled) return;
      if (!this.ready) throw new Error("Audio is suspended");
      const start = this.context.currentTime;
      for (const [offset, frequency] of [[0,660],[0.24,880]]) {
        const tone = this.context.createOscillator(), gain = this.context.createGain();
        tone.type = "sine"; tone.frequency.value = frequency;
        gain.gain.setValueAtTime(0, start+offset);
        gain.gain.linearRampToValueAtTime(0.65, start+offset+0.015);
        gain.gain.setValueAtTime(0.65, start+offset+0.09);
        gain.gain.exponentialRampToValueAtTime(0.001, start+offset+0.21);
        tone.connect(gain); gain.connect(this.context.destination);
        tone.start(start+offset); tone.stop(start+offset+0.23);
        tone.onended = () => { tone.disconnect(); gain.disconnect(); };
      }
    }
  }
  function remainingGrantSeconds(remaining, receivedAt, now) {
    if (!Number.isFinite(remaining)) return null;
    return Math.max(0, Math.ceil(remaining - Math.max(0, now-receivedAt)/1000));
  }
  if (typeof module !== "undefined" && module.exports) module.exports = {RequestNotifications, RequestSound, remainingGrantSeconds};
  else { root.RequestNotifications = RequestNotifications; root.RequestSound = RequestSound; root.remainingGrantSeconds = remainingGrantSeconds; }
})(typeof window === "undefined" ? globalThis : window);

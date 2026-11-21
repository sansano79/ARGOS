/**
 * Limitador de ventana deslizante por clave. Garantiza como mucho `limit`
 * peticiones en cualquier ventana de `windowMs`.
 */
export class SlidingWindowRateLimiter {
  private readonly calls = new Map<string, number[]>();

  constructor(
    private readonly now: () => number = () => Date.now(),
    private readonly sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
    private readonly windowMs = 60_000,
  ) {}

  async acquire(key: string, limit: number): Promise<void> {
    const max = Math.max(1, Math.floor(limit));
    for (;;) {
      const t = this.now();
      const recent = (this.calls.get(key) || []).filter((ts) => t - ts < this.windowMs);
      if (recent.length < max) {
        recent.push(t);
        this.calls.set(key, recent);
        return;
      }
      this.calls.set(key, recent);
      const waitMs = this.windowMs - (t - recent[0]) + 5;
      await this.sleep(waitMs);
    }
  }
}

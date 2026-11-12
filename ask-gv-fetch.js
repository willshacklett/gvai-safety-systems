(function (root) {
  class RequestError extends Error {
    constructor(kind, status = null) {
      super({
        timeout: "Request timed out. Please try again.",
        aborted: "Request cancelled.",
        network: "Connection unavailable. Please try again.",
        http: "Service temporarily unavailable. Please try again.",
        json: "Service returned an invalid response. Please try again."
      }[kind]);
      this.name = "RequestError";
      this.kind = kind;
      this.status = status;
    }
  }

  async function fetchJSON(url, options = {}) {
    const { timeoutMs = 25000, signal, ...requestOptions } = options;
    const controller = new AbortController();
    let timedOut = false;
    const cancellation = new Promise((resolve, reject) => {
      controller.signal.addEventListener("abort", () => {
        reject(new RequestError(timedOut ? "timeout" : "aborted"));
      }, { once: true });
    });
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      const operation = async () => {
        if (controller.signal.aborted) throw new RequestError("aborted");
        let response;
        try {
          response = await root.fetch(url, { ...requestOptions, signal: controller.signal });
        } catch (error) {
          throw new RequestError(controller.signal.aborted ? (timedOut ? "timeout" : "aborted") : "network");
        }
        if (!response.ok) throw new RequestError("http", response.status);
        let data;
        try {
          data = await response.json();
        } catch (error) {
          throw new RequestError("json");
        }
        return { ok: true, status: response.status, headers: response.headers, json: async () => data };
      };
      return await Promise.race([operation(), cancellation]);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
  root.GVAI = { ...root.GVAI, fetchJSON, RequestError };
  if (typeof module !== "undefined" && module.exports) module.exports = root.GVAI;
})(globalThis);

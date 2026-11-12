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
    const { timeoutMs = 20000, maxBytes = 16384, signal, ...requestOptions } = options;
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
          if(!Number.isSafeInteger(maxBytes) || maxBytes<1 || maxBytes>32768 || !response.headers.get('content-type')?.startsWith('application/json'))throw Error('response');
          if(Number(response.headers.get('content-length'))>maxBytes)throw Error('size');
          const reader=response.body.getReader();let bytes=0;const parts=[];
          try {
            while(true) {const {value,done}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>maxBytes)throw Error('size');parts.push(value);}
          } finally {await reader.cancel().catch(()=>{});reader.releaseLock();}
          const all=new Uint8Array(bytes);let offset=0;for(const part of parts){all.set(part,offset);offset+=part.byteLength;}
          data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));
        } catch (error) {
          throw new RequestError("json");
        }
        return { ok: true, status: response.status, headers: response.headers, json: async () => data };
      };
      return await Promise.race([operation(), cancellation]);
    } finally {
      clearTimeout(timer);
      controller.abort();
      signal?.removeEventListener("abort", abort);
    }
  }
  root.GVAI = { ...root.GVAI, fetchJSON, RequestError };
  if (typeof module !== "undefined" && module.exports) module.exports = root.GVAI;
})(globalThis);

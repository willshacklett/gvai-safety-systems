// CLI test preload: deny all outbound provider fetches before importing production code.
globalThis.fetch = () => { throw Error('unmocked_provider_disabled'); };

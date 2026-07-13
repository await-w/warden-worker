/**
 * JS wrapper entry point.
 *
 * Route selected hot-path APIs to HEAVY_DO to avoid Worker CPU timeout,
 * while keeping the rest of requests on the Rust WASM worker.
 */

import RustWorker from "../build/index.js";
import {
  getHeavyDoName,
  normalizePathname,
  shouldOffloadToHeavyDo,
} from "./heavy_do_routing.mjs";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);

    if (env.HEAVY_DO && shouldOffloadToHeavyDo(url.pathname)) {
      const stub = env.HEAVY_DO.getByName(getHeavyDoName());
      return stub.fetch(request);
    }

    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },

  async scheduled(event, env, ctx) {
    const worker = new RustWorker(ctx, env);
    return worker.scheduled(event);
  },
};

export { NotificationsHub, HeavyDo } from "../build/index.js";

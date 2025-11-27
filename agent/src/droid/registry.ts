import route from "./router.js";
import { createRegistry, type RemoteRPC } from "../common/registry.js";

const { invoke, interfaces } = createRegistry(route);

export { invoke, interfaces };

// some typescript magic
export type RPCRoute = typeof route;

export type { RemoteRPC };

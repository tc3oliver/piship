/** Public upstream entrypoints for the portable Node bundle. */

import { setBedrockProviderModule } from "@earendil-works/pi-ai/api/bedrock-converse-stream.lazy";
import { bedrockProviderModule } from "@earendil-works/pi-ai/bedrock-provider";
import { registerBunOAuthFlows } from "@earendil-works/pi-ai/bun-oauth";

// These upstream APIs also support a Node bundle: they avoid variable imports
// whose paths disappear when provider modules are combined into shared chunks.
registerBunOAuthFlows();
setBedrockProviderModule(bedrockProviderModule);

export * from "./index.js";

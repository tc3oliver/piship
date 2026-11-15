/** Public upstream entrypoints for the portable Node bundle. */
import { registerBunOAuthFlows } from "@earendil-works/pi-ai/bun-oauth";
import { bedrockProviderModule } from "@earendil-works/pi-ai/bedrock-provider";
import { setBedrockProviderModule } from "@earendil-works/pi-ai/api/bedrock-converse-stream.lazy";

// These upstream APIs also support a Node bundle: they avoid variable imports
// whose paths disappear when provider modules are combined into shared chunks.
registerBunOAuthFlows();
setBedrockProviderModule(bedrockProviderModule);
export * from "./index.js";

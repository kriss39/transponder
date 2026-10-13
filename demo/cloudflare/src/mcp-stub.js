// mppx loads @modelcontextprotocol/sdk only to answer MCP tool calls. This
// Worker serves plain HTTP, so that path never runs; the alias in
// wrangler.toml points the import here instead of bundling the MCP SDK.
export class McpError extends Error {
  constructor(code, message, data) {
    super(message)
    this.code = code
    this.data = data
  }
}

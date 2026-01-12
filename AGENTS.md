# igf Monorepo

This is a monorepo project for a mobile security auditing tool.

## Project Structure

- `agent`: Contains frida agent code to run on remote mobile system (iOS and Android)
- `gui`: React web using shadcn/ui
- `src`: Frida server backend, also to host the webui

## Guidelines for Code Agents

Default to using Bun instead of Node.js.

- Use `bun <file>` instead of `node <file>` or `ts-node <file>`
- Use `bun test` instead of `jest` or `vitest`
- Use `bun install` instead of `npm install`
- Use `bun run <script>` instead of `npm run <script>` or `yarn run <script>` or `pnpm run <script>`
- Bun automatically loads .env, so don't use dotenv.

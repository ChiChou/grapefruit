import RemoteStreamController from "frida-remote-stream";
import { Readable } from "node:stream";
import type { StreamingApi } from "hono/utils/stream";
import type { Device, ScriptExports, ScriptMessageHandler } from "./xvii.ts";
import { agent } from "./assets.ts";

export class Transport {
  constructor(
    public readonly script: {
      exports: ScriptExports;
      unload: () => Promise<void>;
      message: { connect: (handler: ScriptMessageHandler) => void };
      post: (message: object, data?: Buffer | null) => void;
    },
    public readonly session: { detach: () => Promise<void> },
    public readonly controller: RemoteStreamController,
  ) {}

  async close(): Promise<void> {
    await this.script.unload();
    await this.session.detach();
  }

  /** Pull a remote stream and pipe it into a Hono streaming response. */
  async pipe(streamer: StreamingApi, pull: () => Promise<void>): Promise<void> {
    await Promise.all([
      new Promise<void>((resolve) => {
        this.controller.events.on("stream", async (incoming: Readable) => {
          for await (const chunk of incoming) {
            await streamer.write(chunk);
          }
          await this.close();
          resolve();
        });
      }),
      pull(),
    ]);
  }
}

export async function create(device: Device, pid: number): Promise<Transport> {
  const agentSource = await agent("transport");
  const session = await device.attach(pid);
  const script = await session.createScript(agentSource);
  await script.load();

  const controller = new RemoteStreamController();
  controller.events.on("send", ({ stanza, data }) => {
    script.post(
      {
        type: "+stream",
        payload: stanza,
      },
      data,
    );
  });

  script.message.connect((message, data) => {
    if (message.type === "send") {
      const stanza = message.payload as {
        payload: { [key: string]: any };
        name: string;
      };
      if (stanza.name === "+stream") {
        controller.receive({
          stanza: stanza.payload,
          data,
        });
      }
    }
  });

  return new Transport(script, session, controller);
}

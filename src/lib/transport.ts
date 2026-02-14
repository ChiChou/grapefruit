import RemoteStreamController from "frida-remote-stream";
import type { Device, ScriptExports } from "./xvii.ts";
import { agent } from "./assets.ts";

export class Transport {
  constructor(
    public readonly script: {
      exports: ScriptExports;
      unload: () => Promise<void>;
    },
    public readonly session: { detach: () => Promise<void> },
    public readonly controller: RemoteStreamController,
  ) {}

  async close(): Promise<void> {
    await this.script.unload();
    await this.session.detach();
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

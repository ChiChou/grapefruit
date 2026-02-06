import cf from "@/fruity/native/corefoundation.js";
import { BaseMessage, bt } from "@/common/hooks/context.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "crypto";
  op?: "decrypt" | "encrypt";
  algo?: string;
  details?: {
    type: "input" | "output" | "key";
    len?: number;
  };
}

const CC_ALGORITHMS = ["AES", "DES", "3DES", "CAST", "RC4", "RC2"];
const HMAC_ALGORITHMS = ["SHA1", "MD5", "SHA256", "SHA384", "SHA512", "SHA224"];

export function x509() {
  const Security = Process.findModuleByName("Security");
  if (!Security) return [];

  return [
    Interceptor.attach(
      Security.getExportByName("SecCertificateCreateWithData"),
      {
        onEnter(args) {
          const { CFDataGetLength, CFDataGetBytePtr } = cf();
          const p = CFDataGetBytePtr(args[1]);
          const len = CFDataGetLength(args[1]);
          const der = p.readByteArray(len);

          const detail: Message = {
            subject: "hook",
            category: "crypto",
            symbol: "SecCertificateCreateWithData",
            dir: "enter",
            line: `SecCertificateCreateWithData(data[${len}])`,
            backtrace: bt(this.context),
          };

          send(detail, der);
        },
      },
    ),
  ];
}

export function cccrypt() {
  const cc = Process.findModuleByName("libcommonCrypto.dylib");
  if (!cc) return [];

  return [
    "CCCryptorCreate",
    "CCCryptorCreateFromData",
    "CCCryptorUpdate",
    "CCCryptorFinal",
    "CCCrypt",
    "CCCryptorReset",
  ]
    .map((sym) => {
      const addr = cc.getExportByName(sym);
      if (!addr) return null;

      return Interceptor.attach(addr, {
        onEnter(args) {
          this.symbol = sym;
          const detail: Message = {
            subject: "hook",
            category: "crypto",
            symbol: sym,
            dir: "enter",
            backtrace: bt(this.context),
          };

          if (
            sym === "CCCryptorCreate" ||
            sym === "CCCryptorCreateFromData" ||
            sym === "CCCrypt"
          ) {
            const op = args[0].toInt32();
            const alg = args[1].toInt32();
            detail.op = op === 0 ? "encrypt" : "decrypt";
            detail.algo = CC_ALGORITHMS[alg] || "Unknown";

            const keyLen = args[4].toInt32();
            const key = args[3].readByteArray(keyLen);
            detail.line = `${sym}(${detail.op}, ${detail.algo}, key[${keyLen}])`;
            send({ ...detail, details: { type: "key" } }, key);
          }

          if (sym === "CCCryptorUpdate" || sym === "CCCrypt") {
            const dataInIdx = sym === "CCCrypt" ? 6 : 1;
            const lenIdx = sym === "CCCrypt" ? 7 : 2;
            const len = args[lenIdx].toInt32();
            const data = args[dataInIdx].readByteArray(len);

            detail.details = { type: "input", len: len };
            detail.line = `${sym}(input[${len}])`;
            send(detail, data);

            this.outPtr = args[sym === "CCCrypt" ? 8 : 3];
            this.movedPtr = args[sym === "CCCrypt" ? 10 : 5];
          }

          if (sym === "CCCryptorFinal") {
            this.outPtr = args[1];
            this.movedPtr = args[3];
            detail.line = `${sym}()`;
            send(detail);
          }
        },
        onLeave(retval) {
          if (
            this.outPtr &&
            !this.outPtr.isNull() &&
            this.movedPtr &&
            !this.movedPtr.isNull()
          ) {
            const moved = this.movedPtr.readPointer().toInt32();
            if (moved > 0) {
              const outData = this.outPtr.readByteArray(moved);
              const leaveMsg: Message = {
                subject: "hook",
                category: "crypto",
                symbol: this.symbol,
                dir: "leave",
                line: `${this.symbol}() → output[${moved}]`,
                details: { type: "output", len: moved },
              };
              send(leaveMsg, outData);
            }
          }
        },
      });
    })
    .filter((h) => h !== null);
}

export function hash() {
  const cc = Process.findModuleByName("libcommonCrypto.dylib");
  if (!cc) return [];

  const algs = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"];
  const hooks: InvocationListener[] = [];

  for (const alg of algs) {
    const oneShot = cc.getExportByName(`CC_${alg}`);
    if (oneShot) {
      hooks.push(
        Interceptor.attach(oneShot, {
          onEnter(args) {
            const len = args[1].toInt32();
            send(
              {
                subject: "hook",
                category: "crypto",
                symbol: `CC_${alg}`,
                dir: "enter",
                line: `CC_${alg}(data[${len}])`,
                backtrace: bt(this.context),
              },
              args[0].readByteArray(len),
            );
          },
        }),
      );
    }

    const update = cc.getExportByName(`CC_${alg}_Update`);
    if (update) {
      hooks.push(
        Interceptor.attach(update, {
          onEnter(args) {
            const len = args[2].toInt32();
            send(
              {
                subject: "hook",
                category: "crypto",
                symbol: `CC_${alg}_Update`,
                dir: "enter",
                line: `CC_${alg}_Update(data[${len}])`,
                backtrace: bt(this.context),
              },
              args[1].readByteArray(len),
            );
          },
        }),
      );
    }
  }
  return hooks;
}

export function hmac() {
  const cc = Process.findModuleByName("libcommonCrypto.dylib");
  if (!cc) return [];

  const hooks: InvocationListener[] = [];

  hooks.push(
    Interceptor.attach(cc.getExportByName("CCHmac"), {
      onEnter(args) {
        const alg = args[0].toInt32();
        const keyLen = args[2].toInt32();
        const dataLen = args[4].toInt32();
        const algoName = HMAC_ALGORITHMS[alg] || "Unknown";

        const detail: Message = {
          subject: "hook",
          category: "crypto",
          symbol: "CCHmac",
          dir: "enter",
          line: `CCHmac(${algoName}, key[${keyLen}], data[${dataLen}])`,
          algo: algoName,
          backtrace: bt(this.context),
        };

        send(
          { ...detail, details: { type: "input" } },
          args[3].readByteArray(dataLen),
        );
        send(
          {
            ...detail,
            symbol: "CCHmac_Key",
            line: `CCHmac key[${keyLen}]`,
            details: { type: "key" },
          },
          args[1].readByteArray(keyLen),
        );
      },
    }),
  );

  hooks.push(
    Interceptor.attach(cc.getExportByName("CCHmacUpdate"), {
      onEnter(args) {
        const len = args[2].toInt32();
        send(
          {
            subject: "hook",
            category: "crypto",
            symbol: "CCHmacUpdate",
            dir: "enter",
            line: `CCHmacUpdate(data[${len}])`,
            backtrace: bt(this.context),
          },
          args[1].readByteArray(len),
        );
      },
    }),
  );

  return hooks;
}

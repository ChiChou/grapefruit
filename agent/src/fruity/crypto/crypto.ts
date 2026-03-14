import cf from "@/fruity/native/corefoundation.js";
import { BaseMessage, bt } from "@/common/hooks/context.js";

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

          send(
            {
              subject: "crypto",
              category: "x509",
              symbol: "SecCertificateCreateWithData",
              dir: "enter",
              line: `SecCertificateCreateWithData(data[${len}])`,
              backtrace: bt(this.context),
            } satisfies BaseMessage,
            der,
          );
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

          if (
            sym === "CCCryptorCreate" ||
            sym === "CCCryptorCreateFromData" ||
            sym === "CCCrypt"
          ) {
            const opVal = args[0].toInt32();
            const alg = args[1].toInt32();
            const op = opVal === 0 ? "encrypt" : "decrypt";
            const algo = CC_ALGORITHMS[alg] || "Unknown";

            const keyLen = args[4].toInt32();
            const key = args[3].readByteArray(keyLen);
            send(
              {
                subject: "crypto",
                category: "cccrypt",
                symbol: sym,
                dir: "enter",
                line: `${sym}(${op}, ${algo}, key[${keyLen}])`,
                backtrace: bt(this.context),
                extra: { op, algo, detailType: "key" },
              } satisfies BaseMessage,
              key,
            );
          }

          if (sym === "CCCryptorUpdate" || sym === "CCCrypt") {
            const dataInIdx = sym === "CCCrypt" ? 6 : 1;
            const lenIdx = sym === "CCCrypt" ? 7 : 2;
            const len = args[lenIdx].toInt32();
            const data = args[dataInIdx].readByteArray(len);

            send(
              {
                subject: "crypto",
                category: "cccrypt",
                symbol: sym,
                dir: "enter",
                line: `${sym}(input[${len}])`,
                backtrace: bt(this.context),
                extra: { detailType: "input", len },
              } satisfies BaseMessage,
              data,
            );

            this.outPtr = args[sym === "CCCrypt" ? 8 : 3];
            this.movedPtr = args[sym === "CCCrypt" ? 10 : 5];
          }

          if (sym === "CCCryptorFinal") {
            this.outPtr = args[1];
            this.movedPtr = args[3];
            send({
              subject: "crypto",
              category: "cccrypt",
              symbol: sym,
              dir: "enter",
              line: `${sym}()`,
              backtrace: bt(this.context),
            } satisfies BaseMessage);
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
              send(
                {
                  subject: "crypto",
                  category: "cccrypt",
                  symbol: this.symbol,
                  dir: "leave",
                  line: `${this.symbol}() → output[${moved}]`,
                  extra: { detailType: "output", len: moved },
                } satisfies BaseMessage,
                outData,
              );
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
            const backtrace = bt(this.context);

            // workaround: MobileGestalt uses MD5 to obfuscate strings, abvoid
            // todo: limit all hooks to app binaries only
            if (backtrace.at(0)?.startsWith("libMobileGestalt.dylib")) return;

            send(
              {
                subject: "crypto",
                category: "hash",
                symbol: `CC_${alg}`,
                dir: "enter",
                line: `CC_${alg}(data[${len}])`,
                backtrace,
                extra: { algo: alg, detailType: "input", len },
              } satisfies BaseMessage,
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
                subject: "crypto",
                category: "hash",
                symbol: `CC_${alg}_Update`,
                dir: "enter",
                line: `CC_${alg}_Update(data[${len}])`,
                backtrace: bt(this.context),
                extra: { algo: alg, detailType: "input", len },
              } satisfies BaseMessage,
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
        const algo = HMAC_ALGORITHMS[alg] || "Unknown";

        send(
          {
            subject: "crypto",
            category: "hmac",
            symbol: "CCHmac",
            dir: "enter",
            line: `CCHmac(${algo}, key[${keyLen}], data[${dataLen}])`,
            backtrace: bt(this.context),
            extra: { algo, detailType: "input", len: dataLen },
          } satisfies BaseMessage,
          args[3].readByteArray(dataLen),
        );
        send(
          {
            subject: "crypto",
            category: "hmac",
            symbol: "CCHmac_Key",
            dir: "enter",
            line: `CCHmac key[${keyLen}]`,
            backtrace: bt(this.context),
            extra: { algo, detailType: "key", len: keyLen },
          } satisfies BaseMessage,
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
            subject: "crypto",
            category: "hmac",
            symbol: "CCHmacUpdate",
            dir: "enter",
            line: `CCHmacUpdate(data[${len}])`,
            backtrace: bt(this.context),
            extra: { detailType: "input", len },
          } satisfies BaseMessage,
          args[1].readByteArray(len),
        );
      },
    }),
  );

  return hooks;
}

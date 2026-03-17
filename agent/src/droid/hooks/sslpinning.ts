import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook, bt } from "@/common/hooks/java.js";

const hooks: InvocationListener[] = [];
let running = false;

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    try {
      hookSSLContext();
    } catch (e) {
      console.warn("sslpinning: SSLContext hooks unavailable:", e);
    }
    try {
      hookHostnameVerifier();
    } catch (e) {
      console.warn("sslpinning: HostnameVerifier hooks unavailable:", e);
    }
    try {
      hookTrustManager();
    } catch (e) {
      console.warn("sslpinning: TrustManager hooks unavailable:", e);
    }
    try {
      hookOkHttp();
    } catch (e) {
      console.warn("sslpinning: OkHttp hooks unavailable:", e);
    }
  });
}

function hookSSLContext() {
  const SSLContext = Java.use("javax.net.ssl.SSLContext");

  // SSLContext.init(KeyManager[], TrustManager[], SecureRandom)
  hooks.push(
    hook(
      SSLContext.init,
      (original, self, args) => {
        const [keyManagers, trustManagers, secureRandom] = args as [
          Java.Wrapper | null,
          Java.Wrapper | null,
          Java.Wrapper | null,
        ];

        let detail = "SSLContext.init called";
        let risk: "critical" | "high" = "high";

        if (trustManagers !== null) {
          try {
            const len = Java.cast(
              trustManagers,
              Java.use("[Ljavax.net.ssl.TrustManager;"),
            ).length;
            if (len > 0) {
              const tm = Java.cast(
                trustManagers,
                Java.use("[Ljavax.net.ssl.TrustManager;"),
              )[0];
              const tmClass = Java.cast(tm, Java.use("java.lang.Object"))
                .$className;
              detail = `Custom TrustManager installed: ${tmClass}`;
              risk = "critical";
            }
          } catch {
            detail = "Custom TrustManager array passed to SSLContext.init";
            risk = "critical";
          }
        }

        const kmStr = keyManagers === null ? "null" : "KeyManager[]";
        const tmStr = trustManagers === null ? "null" : "TrustManager[]";
        const srStr = secureRandom === null ? "null" : "SecureRandom";

        send({
          subject: "hook",
          category: "sslpinning",
          symbol: "SSLContext.init",
          dir: "enter",
          line: `SSLContext.init(${kmStr}, ${tmStr}, ${srStr})${trustManagers !== null ? " \u26a0\ufe0f Custom TrustManager" : ""}`,
          backtrace: bt(),
          extra: { risk, detail },
        } satisfies BaseMessage);

        return original.call(self, keyManagers, trustManagers, secureRandom);
      },
    ),
  );
}

function hookHostnameVerifier() {
  const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

  // setDefaultHostnameVerifier(HostnameVerifier)
  hooks.push(
    hook(
      HttpsURLConnection.setDefaultHostnameVerifier,
      (original, self, args) => {
        const [verifier] = args as [Java.Wrapper | null];

        let verifierClass = "<unknown>";
        try {
          if (verifier !== null) {
            verifierClass = Java.cast(
              verifier,
              Java.use("java.lang.Object"),
            ).$className;
          }
        } catch {
          /* ignore */
        }

        send({
          subject: "hook",
          category: "sslpinning",
          symbol: "HttpsURLConnection.setDefaultHostnameVerifier",
          dir: "enter",
          line: `setDefaultHostnameVerifier(${verifierClass}) \u26a0\ufe0f Custom global HostnameVerifier`,
          backtrace: bt(),
          extra: {
            risk: "critical" as const,
            detail: `Global HostnameVerifier replaced with ${verifierClass}`,
          },
        } satisfies BaseMessage);

        return original.call(self, verifier);
      },
    ),
  );

  // setHostnameVerifier(HostnameVerifier) - per-connection
  hooks.push(
    hook(
      HttpsURLConnection.setHostnameVerifier,
      (original, self, args) => {
        const [verifier] = args as [Java.Wrapper | null];

        let verifierClass = "<unknown>";
        try {
          if (verifier !== null) {
            verifierClass = Java.cast(
              verifier,
              Java.use("java.lang.Object"),
            ).$className;
          }
        } catch {
          /* ignore */
        }

        send({
          subject: "hook",
          category: "sslpinning",
          symbol: "HttpsURLConnection.setHostnameVerifier",
          dir: "enter",
          line: `setHostnameVerifier(${verifierClass}) \u26a0\ufe0f Custom HostnameVerifier`,
          backtrace: bt(),
          extra: {
            risk: "high" as const,
            detail: `Per-connection HostnameVerifier set to ${verifierClass}`,
          },
        } satisfies BaseMessage);

        return original.call(self, verifier);
      },
    ),
  );
}

function hookTrustManager() {
  // Hook TrustManagerFactory.getTrustManagers() to detect custom TrustManager retrieval
  const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");

  hooks.push(
    hook(
      TrustManagerFactory.getTrustManagers,
      (original, self, args) => {
        const result = original.call(self, ...args);

        send({
          subject: "hook",
          category: "sslpinning",
          symbol: "TrustManagerFactory.getTrustManagers",
          dir: "enter",
          line: `TrustManagerFactory.getTrustManagers()`,
          backtrace: bt(),
          extra: {
            risk: "high" as const,
            detail: "TrustManagers retrieved from TrustManagerFactory",
          },
        } satisfies BaseMessage);

        return result;
      },
    ),
  );

  // Hook the platform default X509TrustManager implementations
  const platformClasses = [
    "com.android.org.conscrypt.TrustManagerImpl",
    "org.conscrypt.TrustManagerImpl",
    "org.conscrypt.Platform",
  ];

  for (const className of platformClasses) {
    try {
      const cls = Java.use(className);

      // checkServerTrusted
      try {
        hooks.push(
          hook(
            cls.checkServerTrusted.overload(
              "[Ljava.security.cert.X509Certificate;",
              "java.lang.String",
            ),
            (original, self, args) => {
              send({
                subject: "hook",
                category: "sslpinning",
                symbol: "X509TrustManager.checkServerTrusted",
                dir: "enter",
                line: `${className}.checkServerTrusted() called`,
                backtrace: bt(),
                extra: {
                  risk: "critical" as const,
                  detail: `checkServerTrusted invoked on ${className}`,
                },
              } satisfies BaseMessage);

              return original.call(self, ...args);
            },
          ),
        );
      } catch {
        /* overload may not exist */
      }

      // checkClientTrusted
      try {
        hooks.push(
          hook(
            cls.checkClientTrusted.overload(
              "[Ljava.security.cert.X509Certificate;",
              "java.lang.String",
            ),
            (original, self, args) => {
              send({
                subject: "hook",
                category: "sslpinning",
                symbol: "X509TrustManager.checkClientTrusted",
                dir: "enter",
                line: `${className}.checkClientTrusted() called`,
                backtrace: bt(),
                extra: {
                  risk: "high" as const,
                  detail: `checkClientTrusted invoked on ${className}`,
                },
              } satisfies BaseMessage);

              return original.call(self, ...args);
            },
          ),
        );
      } catch {
        /* overload may not exist */
      }

      // getAcceptedIssuers
      try {
        hooks.push(
          hook(
            cls.getAcceptedIssuers,
            (original, self, args) => {
              const result = original.call(self, ...args);

              let isEmpty = false;
              try {
                if (result === null || (result as Java.Wrapper).length === 0) {
                  isEmpty = true;
                }
              } catch {
                /* ignore */
              }

              if (isEmpty) {
                send({
                  subject: "hook",
                  category: "sslpinning",
                  symbol: "X509TrustManager.getAcceptedIssuers",
                  dir: "enter",
                  line: `${className}.getAcceptedIssuers() returned empty \u26a0\ufe0f Trust-all pattern`,
                  backtrace: bt(),
                  extra: {
                    risk: "high" as const,
                    detail: `getAcceptedIssuers on ${className} returned empty array — trust-all pattern`,
                  },
                } satisfies BaseMessage);
              }

              return result;
            },
          ),
        );
      } catch {
        /* method may not exist */
      }
    } catch {
      /* class not available on this device */
    }
  }
}

function hookOkHttp() {
  const Builder = Java.use("okhttp3.OkHttpClient$Builder");

  // sslSocketFactory(SSLSocketFactory, X509TrustManager)
  try {
    hooks.push(
      hook(
        Builder.sslSocketFactory.overload(
          "javax.net.ssl.SSLSocketFactory",
          "javax.net.ssl.X509TrustManager",
        ),
        (original, self, args) => {
          const [factory, trustManager] = args as [Java.Wrapper, Java.Wrapper];

          let factoryClass = "<unknown>";
          let tmClass = "<unknown>";
          try {
            factoryClass = Java.cast(
              factory,
              Java.use("java.lang.Object"),
            ).$className;
            tmClass = Java.cast(
              trustManager,
              Java.use("java.lang.Object"),
            ).$className;
          } catch {
            /* ignore */
          }

          send({
            subject: "hook",
            category: "sslpinning",
            symbol: "OkHttpClient.Builder.sslSocketFactory",
            dir: "enter",
            line: `sslSocketFactory(${factoryClass}, ${tmClass}) \u26a0\ufe0f Custom SSL factory`,
            backtrace: bt(),
            extra: {
              risk: "critical" as const,
              detail: `OkHttp custom SSLSocketFactory: ${factoryClass}, TrustManager: ${tmClass}`,
            },
          } satisfies BaseMessage);

          return original.call(self, factory, trustManager);
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }

  // hostnameVerifier(HostnameVerifier)
  try {
    hooks.push(
      hook(
        Builder.hostnameVerifier,
        (original, self, args) => {
          const [verifier] = args as [Java.Wrapper];

          let verifierClass = "<unknown>";
          try {
            verifierClass = Java.cast(
              verifier,
              Java.use("java.lang.Object"),
            ).$className;
          } catch {
            /* ignore */
          }

          send({
            subject: "hook",
            category: "sslpinning",
            symbol: "OkHttpClient.Builder.hostnameVerifier",
            dir: "enter",
            line: `hostnameVerifier(${verifierClass}) \u26a0\ufe0f Custom hostname verifier`,
            backtrace: bt(),
            extra: {
              risk: "high" as const,
              detail: `OkHttp custom HostnameVerifier: ${verifierClass}`,
            },
          } satisfies BaseMessage);

          return original.call(self, verifier);
        },
      ),
    );
  } catch {
    /* method may not exist */
  }
}

export function stop() {
  for (const h of hooks) {
    try {
      h.detach();
    } catch {
      /* ignore */
    }
  }
  hooks.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  if (!Java.available) return false;
  let found = false;
  Java.perform(() => {
    try {
      Java.use("javax.net.ssl.SSLContext");
      found = true;
    } catch {
      /* not found */
    }
  });
  return found;
}

import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";

export interface KeystoreAlias {
  alias: string;
  algorithm: string | null;
  entryType: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  sigAlgName: string;
  type: string;
  pem: string;
}

export interface KeyInfo {
  alias: string;
  algorithm: string;
  keySize: number;
  blockModes: string[];
  digests: string[];
  encryptionPaddings: string[];
  signaturePaddings: string[];
  purposes: number;
  origin: number;
  isInsideSecureHardware: boolean;
  isUserAuthenticationRequired: boolean;
  userAuthenticationValidityDurationSeconds: number;
  isInvalidatedByBiometricEnrollment: boolean;
  isTrustedUserPresenceRequired: boolean | null;
  isUserConfirmationRequired: boolean | null;
  isUserAuthenticationRequirementEnforcedBySecureHardware: boolean;
  isUserAuthenticationValidWhileOnBody: boolean;
  keyValidityStart: string | null;
  keyValidityForOriginationEnd: string | null;
  keyValidityForConsumptionEnd: string | null;
}

function toStringArray(arr: Java.Wrapper | null): string[] {
  if (!arr) return [];
  const result: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    result.push(String(arr[i]));
  }
  return result;
}

export function aliases() {
  return perform(() => {
    const KeyStore = Java.use("java.security.KeyStore");
    const PrivateKeyEntry = Java.use("java.security.KeyStore$PrivateKeyEntry");
    const SecretKeyEntry = Java.use("java.security.KeyStore$SecretKeyEntry");
    const TrustedCertificateEntry = Java.use(
      "java.security.KeyStore$TrustedCertificateEntry",
    );

    const ks = KeyStore.getInstance("AndroidKeyStore");
    ks.load(null);

    const result: KeystoreAlias[] = [];
    const enumeration = ks.aliases();

    while (enumeration.hasMoreElements()) {
      const alias = enumeration.nextElement().toString();
      let algorithm: string | null = null;
      let entryType = "Unknown";

      try {
        if (ks.entryInstanceOf(alias, PrivateKeyEntry.class)) {
          entryType = "PrivateKey";
        } else if (ks.entryInstanceOf(alias, SecretKeyEntry.class)) {
          entryType = "SecretKey";
        } else if (ks.entryInstanceOf(alias, TrustedCertificateEntry.class)) {
          entryType = "TrustedCertificate";
        }
      } catch (_) {
        /* entry type check failed */
      }

      try {
        const key = ks.getKey(alias, null);
        if (key !== null) {
          algorithm = key.getAlgorithm();
        }
      } catch (_) {
        /* key may not be accessible */
      }

      result.push({ alias, algorithm, entryType });
    }

    return result;
  });
}

export function info(alias: string) {
  return perform(() => {
    const KeyStore = Java.use("java.security.KeyStore");
    const KeyFactory = Java.use("java.security.KeyFactory");
    const KeyInfoCls = Java.use("android.security.keystore.KeyInfo");
    const SecretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");

    const ks = KeyStore.getInstance("AndroidKeyStore");
    ks.load(null);

    const key = ks.getKey(alias, null);
    if (key === null) {
      return null;
    }

    const algorithm = key.getAlgorithm();

    let factory: Java.Wrapper;
    try {
      factory = KeyFactory.getInstance(algorithm, "AndroidKeyStore");
    } catch (_) {
      factory = SecretKeyFactory.getInstance(algorithm, "AndroidKeyStore");
    }

    const keyInfo = Java.cast(
      factory.getKeySpec(key, KeyInfoCls.class),
      KeyInfoCls,
    );

    let isTrustedUserPresenceRequired: boolean | null = null;
    try {
      isTrustedUserPresenceRequired = keyInfo.isTrustedUserPresenceRequired();
    } catch (_) {
      /* API level */
    }

    let isUserConfirmationRequired: boolean | null = null;
    try {
      isUserConfirmationRequired = keyInfo.isUserConfirmationRequired();
    } catch (_) {
      /* API level */
    }

    const validityStart = keyInfo.getKeyValidityStart();
    const originationEnd = keyInfo.getKeyValidityForOriginationEnd();
    const consumptionEnd = keyInfo.getKeyValidityForConsumptionEnd();

    return {
      alias: keyInfo.getKeystoreAlias(),
      algorithm,
      keySize: keyInfo.getKeySize(),
      blockModes: toStringArray(keyInfo.getBlockModes()),
      digests: toStringArray(keyInfo.getDigests()),
      encryptionPaddings: toStringArray(keyInfo.getEncryptionPaddings()),
      signaturePaddings: toStringArray(keyInfo.getSignaturePaddings()),
      purposes: keyInfo.getPurposes(),
      origin: keyInfo.getOrigin(),
      isInsideSecureHardware: keyInfo.isInsideSecureHardware(),
      isUserAuthenticationRequired: keyInfo.isUserAuthenticationRequired(),
      userAuthenticationValidityDurationSeconds:
        keyInfo.getUserAuthenticationValidityDurationSeconds(),
      isInvalidatedByBiometricEnrollment:
        keyInfo.isInvalidatedByBiometricEnrollment(),
      isTrustedUserPresenceRequired,
      isUserConfirmationRequired,
      isUserAuthenticationRequirementEnforcedBySecureHardware:
        keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware(),
      isUserAuthenticationValidWhileOnBody:
        keyInfo.isUserAuthenticationValidWhileOnBody(),
      keyValidityStart: validityStart ? validityStart.toString() : null,
      keyValidityForOriginationEnd: originationEnd
        ? originationEnd.toString()
        : null,
      keyValidityForConsumptionEnd: consumptionEnd
        ? consumptionEnd.toString()
        : null,
    } as KeyInfo;
  });
}

export function cert(alias: string) {
  return perform(() => {
    const KeyStore = Java.use("java.security.KeyStore");
    const X509Certificate = Java.use("java.security.cert.X509Certificate");
    const Base64 = Java.use("android.util.Base64");

    const ks = KeyStore.getInstance("AndroidKeyStore");
    ks.load(null);

    const result: CertificateInfo[] = [];

    const chain = ks.getCertificateChain(alias);
    if (chain !== null) {
      for (let i = 0; i < chain.length; i++) {
        const c = Java.cast(chain[i], X509Certificate);
        result.push(extractCert(c, Base64));
      }
    } else {
      const c = ks.getCertificate(alias);
      if (c !== null) {
        result.push(extractCert(Java.cast(c, X509Certificate), Base64));
      }
    }

    return result;
  });
}

function extractCert(
  c: Java.Wrapper,
  Base64: Java.Wrapper,
): CertificateInfo {
  const encoded = c.getEncoded();
  const b64 = Base64.encodeToString(encoded, 0).toString();
  const pem = `-----BEGIN CERTIFICATE-----\n${b64.trim()}\n-----END CERTIFICATE-----`;

  return {
    subject: c.getSubjectDN().toString(),
    issuer: c.getIssuerDN().toString(),
    serial: c.getSerialNumber().toString(),
    notBefore: c.getNotBefore().toString(),
    notAfter: c.getNotAfter().toString(),
    sigAlgName: c.getSigAlgName(),
    type: c.getType(),
    pem,
  };
}

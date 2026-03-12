let cached: {
  SecItemCopyMatching: NativeFunction<
    number,
    [NativePointerValue, NativePointerValue]
  >;
  SecItemAdd: NativeFunction<number, [NativePointerValue, NativePointerValue]>;
  SecItemUpdate: NativeFunction<
    number,
    [NativePointerValue, NativePointerValue]
  >;
  SecItemDelete: NativeFunction<number, [NativePointerValue]>;
  SecAccessControlCreateWithFlags: NativeFunction<
    NativePointer,
    [NativePointerValue, NativePointerValue, number, NativePointerValue]
  >;
  SecAccessControlGetProtection: NativeFunction<
    NativePointer,
    [NativePointerValue]
  >;
  SecAccessControlGetRequirePassword: NativeFunction<
    number,
    [NativePointerValue]
  >;
  SecAccessControlGetConstraint: NativeFunction<
    NativePointer,
    [NativePointerValue, NativePointerValue]
  >;
  SecAccessControlGetConstraints: NativeFunction<
    NativePointer,
    [NativePointerValue]
  >;
  SecStaticCodeCreateWithPath: NativeFunction<
    number,
    [NativePointerValue, number, NativePointerValue]
  >;
  SecCodeCopySigningInformation: NativeFunction<
    number,
    [NativePointerValue, number, NativePointerValue]
  >;
  kSecCodeInfoEntitlementsDict: NativePointer;
  Security: Module;
};

export default function api() {
  if (cached) {
    return cached;
  }

  const Security = Process.getModuleByName("Security");

  const SecItemCopyMatching = new NativeFunction(
    Security.getExportByName("SecItemCopyMatching"),
    "int",
    ["pointer", "pointer"],
  );

  const SecItemAdd = new NativeFunction(
    Security.getExportByName("SecItemAdd"),
    "int",
    ["pointer", "pointer"],
  );

  const SecItemUpdate = new NativeFunction(
    Security.getExportByName("SecItemUpdate"),
    "int",
    ["pointer", "pointer"],
  );

  const SecItemDelete = new NativeFunction(
    Security.getExportByName("SecItemDelete"),
    "int",
    ["pointer"],
  );

  const SecAccessControlCreateWithFlags = new NativeFunction(
    Security.getExportByName("SecAccessControlCreateWithFlags"),
    "pointer",
    ["pointer", "pointer", "int", "pointer"],
  );

  const SecAccessControlGetProtection = new NativeFunction(
    Security.getExportByName("SecAccessControlGetProtection"),
    "pointer",
    ["pointer"],
  );

  const SecAccessControlGetRequirePassword = new NativeFunction(
    Security.getExportByName("SecAccessControlGetRequirePassword"),
    "bool",
    ["pointer"],
  );

  const SecAccessControlGetConstraint = new NativeFunction(
    Security.getExportByName("SecAccessControlGetConstraint"),
    "pointer",
    ["pointer", "pointer"],
  );

  const SecAccessControlGetConstraints = new NativeFunction(
    Security.getExportByName("SecAccessControlGetConstraints"),
    "pointer",
    ["pointer"],
  );

  const SecStaticCodeCreateWithPath = new NativeFunction(
    Security.getExportByName("SecStaticCodeCreateWithPath"),
    "int",
    ["pointer", "uint32", "pointer"],
  );

  const SecCodeCopySigningInformation = new NativeFunction(
    Security.getExportByName("SecCodeCopySigningInformation"),
    "int",
    ["pointer", "uint32", "pointer"],
  );

  const kSecCodeInfoEntitlementsDict = Security.getExportByName(
    "kSecCodeInfoEntitlementsDict",
  ).readPointer();

  cached = {
    SecItemCopyMatching,
    SecItemAdd,
    SecItemUpdate,
    SecItemDelete,
    SecAccessControlCreateWithFlags,
    SecAccessControlGetProtection,
    SecAccessControlGetRequirePassword,
    SecAccessControlGetConstraint,
    SecAccessControlGetConstraints,
    SecStaticCodeCreateWithPath,
    SecCodeCopySigningInformation,
    kSecCodeInfoEntitlementsDict,
    Security,
  };

  return cached;
}

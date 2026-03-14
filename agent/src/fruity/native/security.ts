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
  const e = (name: string) => Security.getExportByName(name);

  const SecItemCopyMatching = new NativeFunction(
    e("SecItemCopyMatching"),
    "int",
    ["pointer", "pointer"],
  );

  const SecItemAdd = new NativeFunction(e("SecItemAdd"), "int", [
    "pointer",
    "pointer",
  ]);

  const SecItemUpdate = new NativeFunction(e("SecItemUpdate"), "int", [
    "pointer",
    "pointer",
  ]);

  const SecItemDelete = new NativeFunction(e("SecItemDelete"), "int", [
    "pointer",
  ]);

  const SecAccessControlCreateWithFlags = new NativeFunction(
    e("SecAccessControlCreateWithFlags"),
    "pointer",
    ["pointer", "pointer", "int", "pointer"],
  );

  const SecAccessControlGetProtection = new NativeFunction(
    e("SecAccessControlGetProtection"),
    "pointer",
    ["pointer"],
  );

  const SecAccessControlGetRequirePassword = new NativeFunction(
    e("SecAccessControlGetRequirePassword"),
    "bool",
    ["pointer"],
  );

  const SecAccessControlGetConstraint = new NativeFunction(
    e("SecAccessControlGetConstraint"),
    "pointer",
    ["pointer", "pointer"],
  );

  const SecAccessControlGetConstraints = new NativeFunction(
    e("SecAccessControlGetConstraints"),
    "pointer",
    ["pointer"],
  );

  const SecStaticCodeCreateWithPath = new NativeFunction(
    e("SecStaticCodeCreateWithPath"),
    "int",
    ["pointer", "uint32", "pointer"],
  );

  const SecCodeCopySigningInformation = new NativeFunction(
    e("SecCodeCopySigningInformation"),
    "int",
    ["pointer", "uint32", "pointer"],
  );

  const kSecCodeInfoEntitlementsDict = e(
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

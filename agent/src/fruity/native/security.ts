export default function api() {
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

  return {
    SecItemCopyMatching,
    SecItemAdd,
    SecItemUpdate,
    SecItemDelete,
    SecAccessControlCreateWithFlags,
    SecAccessControlGetProtection,
    SecAccessControlGetRequirePassword,
    SecAccessControlGetConstraint,
    SecAccessControlGetConstraints,
    Security,
  };
}

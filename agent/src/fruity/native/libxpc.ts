interface XPCTypeEntry {
  name: string;
  address: NativePointer;
}

let cached: {
  libxpc: Module;
  xpc_connection_get_name: NativeFunction<NativePointer, [NativePointerValue]>;
  xpc_connection_get_pid: NativeFunction<number, [NativePointerValue]>;
  xpc_copy_description: NativeFunction<NativePointer, [NativePointerValue]>;
  xpc_get_type: NativeFunction<NativePointer, [NativePointerValue]>;
  xpc_string_get_string_ptr: NativeFunction<
    NativePointer,
    [NativePointerValue]
  >;
  xpc_string_get_length: NativeFunction<UInt64, [NativePointerValue]>;
  xpc_data_get_bytes_ptr: NativeFunction<NativePointer, [NativePointerValue]>;
  xpc_data_get_length: NativeFunction<UInt64, [NativePointerValue]>;
  xpc_uuid_get_bytes: NativeFunction<NativePointer, [NativePointerValue]>;
  xpc_double_get_value: NativeFunction<number, [NativePointerValue]>;
  xpc_bool_get_value: NativeFunction<number, [NativePointerValue]>;
  xpc_int64_get_value: NativeFunction<Int64, [NativePointerValue]>;
  xpc_uint64_get_value: NativeFunction<UInt64, [NativePointerValue]>;
  xpc_dictionary_apply: NativeFunction<
    number,
    [NativePointerValue, NativePointerValue]
  >;
  xpc_array_apply: NativeFunction<
    number,
    [NativePointerValue, NativePointerValue]
  >;
  xpc_fd_dup: NativeFunction<number, [NativePointerValue]>;
  xpc_date_get_value: NativeFunction<Int64, [NativePointerValue]>;
  xpcTypes: XPCTypeEntry[];
  xpcDictionaryType: NativePointer;
  xpcArrayType: NativePointer;
};

export default function api() {
  if (cached) return cached;

  const libxpc = Process.getModuleByName("libxpc.dylib");

  const e = (name: string) => libxpc.getExportByName(name);

  const xpcTypes = libxpc
    .enumerateExports()
    .filter((s) => s.name.startsWith("_xpc_type_"))
    .map((s) => ({ name: s.name, address: s.address }));

  cached = {
    libxpc,
    xpc_connection_get_name: new NativeFunction(
      e("xpc_connection_get_name"),
      "pointer",
      ["pointer"],
    ),
    xpc_connection_get_pid: new NativeFunction(
      e("xpc_connection_get_pid"),
      "int",
      ["pointer"],
    ),
    xpc_copy_description: new NativeFunction(
      e("xpc_copy_description"),
      "pointer",
      ["pointer"],
    ),
    xpc_get_type: new NativeFunction(e("xpc_get_type"), "pointer", [
      "pointer",
    ]),
    xpc_string_get_string_ptr: new NativeFunction(
      e("xpc_string_get_string_ptr"),
      "pointer",
      ["pointer"],
    ),
    xpc_string_get_length: new NativeFunction(
      e("xpc_string_get_length"),
      "size_t",
      ["pointer"],
    ),
    xpc_data_get_bytes_ptr: new NativeFunction(
      e("xpc_data_get_bytes_ptr"),
      "pointer",
      ["pointer"],
    ),
    xpc_data_get_length: new NativeFunction(
      e("xpc_data_get_length"),
      "size_t",
      ["pointer"],
    ),
    xpc_uuid_get_bytes: new NativeFunction(
      e("xpc_uuid_get_bytes"),
      "pointer",
      ["pointer"],
    ),
    xpc_double_get_value: new NativeFunction(
      e("xpc_double_get_value"),
      "double",
      ["pointer"],
    ),
    xpc_bool_get_value: new NativeFunction(e("xpc_bool_get_value"), "bool", [
      "pointer",
    ]),
    xpc_int64_get_value: new NativeFunction(
      e("xpc_int64_get_value"),
      "int64",
      ["pointer"],
    ),
    xpc_uint64_get_value: new NativeFunction(
      e("xpc_uint64_get_value"),
      "uint64",
      ["pointer"],
    ),
    xpc_dictionary_apply: new NativeFunction(
      e("xpc_dictionary_apply"),
      "bool",
      ["pointer", "pointer"],
    ),
    xpc_array_apply: new NativeFunction(e("xpc_array_apply"), "bool", [
      "pointer",
      "pointer",
    ]),
    xpc_fd_dup: new NativeFunction(e("xpc_fd_dup"), "int", ["pointer"]),
    xpc_date_get_value: new NativeFunction(e("xpc_date_get_value"), "int64", [
      "pointer",
    ]),
    xpcTypes,
    xpcDictionaryType:
      xpcTypes.find((s) => s.name === "_xpc_type_dictionary")?.address ?? NULL,
    xpcArrayType:
      xpcTypes.find((s) => s.name === "_xpc_type_array")?.address ?? NULL,
  };

  return cached;
}

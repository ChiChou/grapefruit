export default function uuid(): string {
  return ObjC.classes.NSUUID.UUID().UUIDString().toString()
}

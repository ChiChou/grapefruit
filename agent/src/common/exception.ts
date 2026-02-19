export function init() {
  Process.setExceptionHandler((detail) => {
    console.error("Exception report: ");
    console.error(JSON.stringify(detail, null, 4));
    send({
      subject: "fatal",
      detail,
    });
    const { context } = detail;
    const pc = Instruction.parse(context.pc);
    console.warn(DebugSymbol.fromAddress(context.pc));
    console.error(pc.toString());
    console.error(Instruction.parse(pc.next).toString());
    console.error("Backtrace");
    console.error(
      Thread.backtrace(context, Backtracer.ACCURATE)
        .map((addr) => DebugSymbol.fromAddress(addr).toString())
        .join("\n"),
    );

    return false;
  });
}

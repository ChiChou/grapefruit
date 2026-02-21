export function init() {
  Process.setExceptionHandler((detail) => {
    console.error("Exception report: ");
    console.error(JSON.stringify(detail, null, 4));
    const { context } = detail;
    const backtrace = Thread.backtrace(context, Backtracer.ACCURATE).map(
      (addr) => DebugSymbol.fromAddress(addr).toString(),
    );
    send({
      subject: "fatal",
      detail: { ...detail, backtrace },
    });
    const pc = Instruction.parse(context.pc);
    console.warn(DebugSymbol.fromAddress(context.pc));
    console.error(pc.toString());
    console.error(Instruction.parse(pc.next).toString());
    console.error("Backtrace");
    console.error(backtrace.join("\n"));

    return false;
  });
}

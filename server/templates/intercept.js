Interceptor.attach(Module.findExportByName("{{ module }}", "{{ name }}"), {
  onEnter(args) {
    // todo: add code here
    console.log("{{ name }} has been called");
    // console.log('{{ name }} called from:\n' +
    //     Thread.backtrace(this.context, Backtracer.ACCURATE)
    //     .map(DebugSymbol.fromAddress).join('\n') + '\n');
  },
  onLeave(retval) {},
});

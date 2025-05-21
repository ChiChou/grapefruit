function requireMinimalVersion(requirement: string) {
  const parse = (ver: string) => ver.split('.').map(s => parseInt(s, 10))
  const a = parse(Frida.version), b = parse(requirement)
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] < b[i])
      throw new Error(`Fatal error: requiring minimum frida version ${requirement}, found ${Frida.version}`)
    if (a[i] > b[i])
      return
  }
}

requireMinimalVersion('12.5')

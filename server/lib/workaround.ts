export const buggy = (() => {
  // a workaround for
  // https://github.com/ChiChou/Grapefruit/issues/20
  // https://github.com/frida/frida-node/issues/61

  const [major,] = process.versions.node.split('.')
  return parseInt(major) > 12
})()

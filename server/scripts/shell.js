const frida = require('frida')
const os = require('os')
const path = require('path')

async function main() {
  const dev = await frida.getUsbDevice()
  const pid = await dev.spawn('/bin/bash', {
    stdio: 'pipe',
    cwd: '/var/root',
  })

  function fix(buf) {
    if (os.EOL === '\n') return buf

    let next = 0
    let left = 0
    const output = []
    const br = Buffer.from('\n')
    while ((next = buf.indexOf(os.EOL, left)) > -1) {
      output.push(buf.slice(left, next))
      output.push(br)
      left = next + 1
    }
    return Buffer.concat(output)
  }

  process.stdin.on('data', data => dev.input(pid, fix(data)))
  const mapping = [null, process.stdout, process.stderr]
  dev.output.connect((processId, fd, data) => {
    if (processId === pid)
      mapping[fd].write(data)
  })

  const session = await dev.attach(pid)
  session.detached.connect(() => process.exit())
  await dev.resume(pid)

  async function cleanup() {
    await session.detach()
    await dev.kill(pid)
  }

  process.on('SIGINT', cleanup)
  process.on('SIGTERM', cleanup)
  process.on('exit', cleanup)
}

main()
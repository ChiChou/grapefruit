#!/usr/bin/env node

const { connect, createServer } = require('net');
const { platform } = require('os');
const fs = require('fs');

const check = (port, host) => new Promise((resolve) => {
  const client = connect({ host, port }, () => {
    resolve(true);
    client.end();
  }).on('error', () => resolve(false));
})

async function bridge(port = 27015) {
  const mapping = {
    wsl: [port, '127.1'],
    docker: [port, 'host.docker.internal']
  };

  const bind = platform() === 'win32' ? { port: 27015, host: '127.1' } : '/var/run/usbmuxd';
  for (let [env, pair] of Object.entries(mapping)) {
    if (await check(...pair)) {
      console.log(`${env} detected`);

      const server = createServer((incoming) => {
        const dst = connect(...pair);
        incoming.pipe(dst);
        dst.pipe(incoming);
        incoming.on('close', () => dst.end());
      }).listen(bind, () => {
        if (typeof bind === 'string')
          fs.chmod(bind, 0777, () => { });
      })

      const cleanup = () => server.close();
      process.on('exit', cleanup);
      process.on('SIGINT', cleanup);
      break;
    }
  }
}

bridge()
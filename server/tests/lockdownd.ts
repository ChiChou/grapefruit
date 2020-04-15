import 'mocha'
import * as frida from 'frida'
import chaiAsPromised from 'chai-as-promised'
import { use, expect } from 'chai'
import { Lockdown } from "../lib/lockdown"

use(chaiAsPromised)

describe('Lockdown', () => {
  let dev: frida.Device

  before(async () => {
    dev = await frida.getUsbDevice();
  })

  // this test case is slow

  // it('should support screenshot', async () => {
  //   const shot = new Lockdown(dev, 'com.apple.mobile.screenshotr')
  //   await shot.connect()
  //   shot.send({ 'MessageType': 'ScreenShotRequest' })
  //   const response = await shot.recv()
  //   shot.close()

  //   expect(response.MessageType).to.eq('ScreenShotReply')
  //   expect(response.ScreenShotData).to.be.instanceOf(Buffer)
  // })

  it('should get device information', async () => {
    const lockdown = new Lockdown(dev)

    await lockdown.connect()
    lockdown.send({
      'Request': 'GetValue'
    });

    const response = await lockdown.recv()
    lockdown.close()
    expect(response.Request).eq('GetValue')
    expect(response.Value).haveOwnProperty('DeviceName')

  })
})
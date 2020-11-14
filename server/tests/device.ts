import * as frida from 'frida'
import chaiAsPromised from 'chai-as-promised'
import { expect, use } from 'chai'
import { wrap } from '../lib/device'

use(chaiAsPromised)

describe('device management', () => {
  it('should', async () => {
    const device = wrap(await frida.getUsbDevice())
    const apps = await device.apps()

    expect(apps).to.be.an('array')
    expect(apps.length).to.be.greaterThan(0)
    expect(apps[0]).to.have.keys('pid', 'identifier', 'largeIcon', 'name', 'smallIcon')
    expect(await device.open('com.apple.mobilesafari', 'about:blank')).to.gt(0)
    expect(device.valueOf()).to.have.keys('name', 'id', 'icon', 'removable', 'type')
    expect(device.host).to.be.null

    try {
      const session = await device.launch('com.apple.calculator')
      await session.detach()
    } catch(_) {
      // iPad has no calculator
    }
  })
})
'use strict'

const { PuppeteerExtraPlugin } = require('puppeteer-extra-plugin')

/**
 * Iframe puppeteer plugin.
 */

class Plugin extends PuppeteerExtraPlugin {
  constructor(opts = {}) {
    super(opts)
  }

  get name() {
    return 'stealth/evasions/device-viewport'
  }

  async onPageCreated(page) {
    this.debug('onPageCreated - Will set these viewport options', {
      opts: this.opts
    })

    await page.evaluateOnNewDocument(device => {
      Object.defineProperty(screen, 'height', {
        get: () => device.viewport.height
      });
      Object.defineProperty(screen, 'width', {
        get: () => device.viewport.width
      });
      Object.defineProperty(window, 'devicePixelRatio', {
        get: () => device.viewport.deviceScaleFactor
      });
    }, this.opts)
  }
}

module.exports = function(pluginConfig) {
  return new Plugin(pluginConfig)
}

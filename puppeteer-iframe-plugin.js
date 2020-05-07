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
    return 'stealth/evasions/iframe'
  }

  async onPageCreated(page) {
    await page.evaluateOnNewDocument(() => {
      const oldCreate = document.createElement.bind(document);
      const newCreate = (...args) => {
          if (args[0] === 'iframe') {
              const iframe = oldCreate(...args);
              if (!iframe.contentWindow) {
                  Object.defineProperty(iframe, 'contentWindow', {
                      configurable: true,
                      value: { chrome: {} },
                  });
              }
              if (!iframe.contentWindow.chrome) {
                  Object.defineProperty(iframe.contentWindow, 'chrome', {
                      value: {},
                      configurable: true,
                  });
              }
              return iframe;
          }
          return oldCreate(...args);
      };

      newCreate.toString = () => 'function createElement() { [native code] }';

      document.createElement = newCreate;

      const oldCall = Function.prototype.call;
      function call() {
          return oldCall.apply(this, arguments);
      }

      Function.prototype.call = call;

      const nativeToStringFunctionString = Error.toString().replace(
          /Error/g,
          'toString',
      );
      const oldToString = Function.prototype.toString;

      function functionToString() {
          if (this === window.document.createElement) {
              return 'function createElement() { [native code] }';
          }
          if (this === functionToString) {
              return nativeToStringFunctionString;
          }
          return oldCall.call(oldToString, this);
      }

      Function.prototype.toString = functionToString
    })
  }
}

module.exports = function(pluginConfig) {
  return new Plugin(pluginConfig)
}

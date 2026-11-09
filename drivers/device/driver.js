'use strict';

const { OAuth2Driver } = require('homey-oauth2app');

// Homey device classes that are safe to hand over; anything else becomes "other".
const VALID_CLASSES = new Set([
  'bridge', 'sensor', 'light', 'switch', 'socket', 'thermostat', 'heater', 'fan',
]);

module.exports = class ThunderHomeDriver extends OAuth2Driver {

  static mapClass(c) {
    return VALID_CLASSES.has(c) ? c : 'other';
  }

  async onOAuth2Init() {
    this.log('ThunderHome driver initialized');
  }

  // Pairing/repair use the default OAuth2 flow (login_oauth2 view -> ThunderHome consent page)

  async onPairListDevices({ oAuth2Client }) {
    const devices = await oAuth2Client.getDevices();

    return devices.map(device => ({
      name: device.name,
      data: { id: device.id },
      class: this.constructor.mapClass(device.class),
      // Capabilities are added dynamically by the device on its first sync,
      // so an unknown capability can never break pairing.
      capabilities: [],
    }));
  }

};
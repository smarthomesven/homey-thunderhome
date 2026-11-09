'use strict';

const { OAuth2Device } = require('homey-oauth2app');

const SYNC_INTERVAL = 5 * 60 * 1000;

module.exports = class ThunderHomeDevice extends OAuth2Device {

  async onOAuth2Init() {
    this._deviceId = this.getData().id;
    this._listening = new Set();
    this._online = null;

    this._onEvent = (type, data) => {
      this._handleEvent(type, data).catch(err => this.error(`Event ${type} failed:`, err.message));
    };
    this._onRealtimeOpen = () => this._queueSync(0);
    this._onAuthExpired = () => this._onSyncError(
      new Error('Authorization expired. Repair this device to sign in to ThunderHome again.'),
    );

    this.oAuth2Client.on('event', this._onEvent);
    this.oAuth2Client.on('realtime:open', this._onRealtimeOpen);
    this.oAuth2Client.on('auth:expired', this._onAuthExpired);
    this.oAuth2Client.connectRealtime();

    await this.sync().catch(err => this._onSyncError(err));

    // Safety net in case a realtime event was missed
    this._syncInterval = this.homey.setInterval(() => {
      this.sync().catch(err => this._onSyncError(err));
    }, SYNC_INTERVAL);
  }

  async onOAuth2Uninit() {
    if (this.oAuth2Client) {
      this.oAuth2Client.removeListener('event', this._onEvent);
      this.oAuth2Client.removeListener('realtime:open', this._onRealtimeOpen);
      this.oAuth2Client.removeListener('auth:expired', this._onAuthExpired);
    }
    this.homey.clearInterval(this._syncInterval);
    this.homey.clearTimeout(this._syncTimeout);
  }

  /* ------------------------------------------------------------------ *
   * Sync
   * ------------------------------------------------------------------ */

  _queueSync(delay = 1000) {
    this.homey.clearTimeout(this._syncTimeout);
    this._syncTimeout = this.homey.setTimeout(() => {
      this.sync().catch(err => this._onSyncError(err));
    }, delay);
  }

  _onSyncError(err) {
    this.error('Sync failed:', err.message);
    this._online = null; // make sure setAvailable() runs again after recovery
    return this.setUnavailable(err.message).catch(this.error);
  }

  async sync() {
    let device;
    try {
      device = await this.oAuth2Client.getDevice(this._deviceId);
    } catch (err) {
      if (err.status === 404) {
        this._online = null;
        await this.setUnavailable('Device not found in ThunderHome');
        return;
      }
      throw err;
    }
    await this._applyDevice(device);
  }

  async _applyDevice(device) {
    // Capabilities
    for (const cap of device.capabilities || []) {
      const id = cap.capability_id;

      if (!this.hasCapability(id)) {
        try {
          await this.addCapability(id);
        } catch (err) {
          this.error(`Cannot add capability ${id}:`, err.message);
          continue;
        }
      }

      const options = {};
      if (cap.min_value != null) options.min = cap.min_value;
      if (cap.max_value != null) options.max = cap.max_value;
      if (cap.step != null) options.step = cap.step;
      if (cap.units) options.units = cap.units;
      if (Object.keys(options).length) {
        await this.setCapabilityOptions(id, options).catch(err => this.error(`Options ${id}:`, err.message));
      }

      if (cap.setable && !this._listening.has(id)) {
        this._listening.add(id);
        this.registerCapabilityListener(id, value => this._setRemote(id, value));
      }

      if (cap.value !== undefined && cap.value !== null) {
        await this._setValue(id, cap.value);
      }
    }

    // Online / offline
    await this._setOnline(device.online !== false);
  }

  async _setOnline(online) {
    if (this._online === online) return;
    this._online = online;
    if (online) await this.setAvailable();
    else await this.setUnavailable('Offline in ThunderHome');
  }

  async _setValue(capabilityId, value) {
    if (!this.hasCapability(capabilityId)) return;
    await this.setCapabilityValue(capabilityId, value).catch(err => this.error(`Set ${capabilityId}:`, err.message));
  }

  async _setRemote(capabilityId, value) {
    await this.oAuth2Client.setCapability(this._deviceId, capabilityId, value);
  }

  /* ------------------------------------------------------------------ *
   * Realtime events
   * ------------------------------------------------------------------ */

  async _handleEvent(type, data) {
    switch (type) {
      case 'device.state': {
        if (String(data.deviceId) !== String(this._deviceId)) return;
        await this._setValue(data.capabilityId, data.value);
        break;
      }

      case 'device.online': {
        if (String(data.deviceId) !== String(this._deviceId)) return;
        await this._setOnline(data.online !== false);
        break;
      }

      case 'devices.changed':
        this._queueSync(1000);
        break;

      default:
        break;
    }
  }

};
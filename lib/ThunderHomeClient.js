'use strict';

const crypto = require('crypto');
const Homey = require('homey');
const axios = require('axios');
const WebSocket = require('ws');
const { OAuth2Client, OAuth2Token, OAuth2Error } = require('homey-oauth2app');

const BASE_URL = 'https://thunderhome.app';
const WS_URL = 'wss://thunderhome.app/';

const b64url = buf => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * Token that also remembers when it expires (access tokens last one hour).
 */
class ThunderHomeToken extends OAuth2Token {

  constructor({ expires_at, ...props }) {
    super({ ...props });
    this.expires_at = expires_at || Date.now() + (Number(props.expires_in) || 3600) * 1000;
  }

  isExpiring(marginMs = 60 * 1000) {
    return Date.now() >= this.expires_at - marginMs;
  }

  toJSON() {
    return { ...super.toJSON(), expires_at: this.expires_at };
  }

}

module.exports = class ThunderHomeClient extends OAuth2Client {

  static API_URL = `${BASE_URL}/api/v1`;
  static TOKEN_URL = `${BASE_URL}/oauth/token`;
  static AUTHORIZATION_URL = `${BASE_URL}/oauth/authorize`;
  static REDIRECT_URL = 'https://callback.athom.com/oauth2/callback'; // register this in ThunderHome
  static SCOPES = ['devices:read', 'devices:control', 'rules:read', 'rules:write', 'rules:run', 'offline_access'];
  static TOKEN = ThunderHomeToken;

  constructor(...args) {
    super(...args);
    this.setMaxListeners(0); // every device subscribes to realtime events
    this._rtWanted = false;
    this._ws = null;
    this._rtAttempt = 0;
  }

  /* ------------------------------------------------------------------ *
   * OAuth2 (authorization code + PKCE S256)
   * ------------------------------------------------------------------ */

  // Step 1: URL the user is sent to (Homey's OAuth2 callback service handles the redirect)
  onHandleAuthorizationURL({ scopes, state } = {}) {
    const { CLIENT_ID: clientId } = Homey.env || {};
    if (!clientId) throw new OAuth2Error('CLIENT_ID missing in env.json');

    this._pkceVerifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(this._pkceVerifier).digest());

    const url = new URL(this.constructor.AUTHORIZATION_URL);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', this.constructor.REDIRECT_URL);
    url.searchParams.set('scope', (scopes && scopes.length ? scopes : this.constructor.SCOPES).join(' '));
    url.searchParams.set('state', state || b64url(crypto.randomBytes(16)));
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  // Step 2: exchange the code (with the PKCE verifier) for an access token
  async onGetTokenByCode({ code }) {
    if (!this._pkceVerifier) {
      throw new OAuth2Error('Missing PKCE verifier, please restart pairing');
    }
    const token = await this._requestToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.constructor.REDIRECT_URL,
      code_verifier: this._pkceVerifier,
    });
    this._pkceVerifier = null;
    this._authFailed = false;
    if (this._rtWanted && !this._ws) {
      this.homey.setTimeout(() => this._openSocket().catch(err => this.error(err.message)), 1000);
    }
    return token;
  }

  // Access tokens last 1 hour. With the offline_access scope ThunderHome also issues rotating,
  // single-use refresh tokens (90 days): every refresh returns a NEW refresh token and revokes the
  // old one, so the new token must be persisted before anything else happens. Homey's
  // refreshToken() de-duplicates parallel calls and holds requests until it is done, which
  // avoids the "reused refresh token" family revocation.
  async onRefreshToken() {
    const current = this.getToken();
    if (!current || !current.isRefreshable()) {
      throw new OAuth2Error('Authorization expired. Repair this device to sign in to ThunderHome again.');
    }

    const token = await this._requestToken({
      grant_type: 'refresh_token',
      refresh_token: current.refresh_token,
    });

    this.setToken({ token });
    await this.save(); // persist the rotated refresh token right away
    return this.getToken();
  }

  async _requestToken(params) {
    const { CLIENT_ID: clientId, CLIENT_SECRET: clientSecret } = Homey.env || {};
    if (!clientId) throw new OAuth2Error('CLIENT_ID missing in env.json');

    const body = new URLSearchParams({ ...params, client_id: clientId });
    if (clientSecret) body.set('client_secret', clientSecret); // optional (confidential client)

    const res = await axios.post(this.constructor.TOKEN_URL, body.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      timeout: 15000,
      validateStatus: () => true, // handle non-2xx ourselves
    });

    const json = res.data && typeof res.data === 'object' ? res.data : null;
    const ok = res.status >= 200 && res.status < 300;

    if (!ok || !json || !json.access_token) {
      const message = (json && (json.error_description || json.error || json.message))
        || `Token request failed (${res.status})`;
      const err = new OAuth2Error(message);
      err.status = res.status;
      throw err;
    }

    return new ThunderHomeToken({
      access_token: json.access_token,
      token_type: json.token_type || 'bearer',
      expires_in: json.expires_in || 3600,
      refresh_token: json.refresh_token || null,
    });
  }

  async onHandleNotOK({ body, status, statusText }) {
    const message = (body && (body.error_description || body.error || body.message)) || statusText;
    const err = new OAuth2Error(message);
    err.status = status;
    throw err;
  }

  /* ------------------------------------------------------------------ *
   * REST
   * ------------------------------------------------------------------ */

  static _list(res, key) {
    if (Array.isArray(res)) return res;
    if (res && Array.isArray(res[key])) return res[key];
    if (res && Array.isArray(res.data)) return res.data;
    return [];
  }

  async getDevice(id) {
    return this.get({ path: `/devices/${encodeURIComponent(id)}` });
  }

  async getDevices() {
    return this.constructor._list(await this.get({ path: '/devices' }), 'devices');
  }

  async getZones() {
    return this.constructor._list(await this.get({ path: '/zones' }), 'zones');
  }

  async getConnectors() {
    return this.constructor._list(await this.get({ path: '/connectors' }), 'connectors');
  }

  async getRules() {
    return this.constructor._list(await this.get({ path: '/rules' }), 'rules');
  }

  async setCapability(deviceId, capabilityId, value) {
    return this.put({
      path: `/devices/${encodeURIComponent(deviceId)}/capabilities/${encodeURIComponent(capabilityId)}`,
      json: { value },
    });
  }

  async rescanConnector(accountId) {
    return this.post({ path: `/connectors/${encodeURIComponent(accountId)}/rescan` });
  }

  async getRule(id) {
    return this.get({ path: `/rules/${encodeURIComponent(id)}` });
  }

  async getRuleCards() {
    return this.get({ path: '/rules/cards' });
  }

  async setRuleEnabled(id, enabled) {
    return this.patch({ path: `/rules/${encodeURIComponent(id)}`, json: { enabled: !!enabled } });
  }

  async createRule(rule) {
    return this.post({ path: '/rules', json: rule });
  }

  async updateRule(id, rule) {
    return this.put({ path: `/rules/${encodeURIComponent(id)}`, json: rule });
  }

  async deleteRule(id) {
    return this.delete({ path: `/rules/${encodeURIComponent(id)}` });
  }

  async runRule(id) {
    return this.post({ path: `/rules/${encodeURIComponent(id)}/run` });
  }

  /* ------------------------------------------------------------------ *
   * Realtime (WebSocket)
   * Emits: 'event' (type, data) and 'realtime:open'
   * ------------------------------------------------------------------ */

  connectRealtime() {
    if (this._rtWanted) return;
    this._rtWanted = true;
    this._openSocket().catch(err => this.error('Realtime connect failed:', err.message));
  }

  async _openSocket() {
    if (!this._rtWanted || this._ws) return;

    try {
      let token = this.getToken();
      if (!token) return;
      if (token.isExpiring()) {
        if (!token.isRefreshable()) {
          this.emit('auth:expired'); // no refresh tokens: user must authorize again
          return;
        }
        try {
          await this.refreshToken();
        } catch (err) {
          this._onRefreshFailed(err);
          return;
        }
        token = this.getToken();
      }

      const ws = new WebSocket(WS_URL, {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });
      this._ws = ws;

      ws.on('open', () => {
        this._rtAttempt = 0;
        this.log('Realtime connected');
        this.emit('realtime:open');
        // The server closes the socket when the token expires
        const refreshable = token.isRefreshable();
        const ms = Math.max(1000, token.expires_at - Date.now() - (refreshable ? 2 * 60 * 1000 : 0));
        this._rtRenewTimer = this.homey.setTimeout(() => {
          if (!refreshable) {
            this.emit('auth:expired');
            return;
          }
          this._closeSocket();
          this._openSocket().catch(err => this.error(err.message));
        }, ms);
      });

      ws.on('message', raw => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg && msg.type) this.emit('event', msg.type, msg);
        } catch (err) {
          this.error('Invalid realtime message:', err.message);
        }
      });

      ws.on('error', err => {
        this.error('Realtime error:', err.message);
        if (/401/.test(err.message)) {
          this._authFailed = true; // blocks the reconnect from 'close' until we know more
          this._onSocketUnauthorized().catch(e => this.error(e.message));
        }
      });

      ws.on('close', () => {
        if (this._ws === ws) this._ws = null;
        this.homey.clearTimeout(this._rtRenewTimer);
        this._scheduleReconnect();
      });
    } catch (err) {
      this.error('Realtime open failed:', err.message);
      this._ws = null;
      this._scheduleReconnect();
    }
  }

  // Handshake rejected with 401: refresh the token if possible, otherwise ask for re-authorization.
  async _onSocketUnauthorized() {
    const token = this.getToken();
    if (token && token.isRefreshable()) {
      try {
        await this.refreshToken();
        this._authFailed = false;
        this._scheduleReconnect();
        return;
      } catch (err) {
        this._onRefreshFailed(err);
        return;
      }
    }
    this.emit('auth:expired');
  }

  _onRefreshFailed(err) {
    this.error('Token refresh failed:', err.message);
    if (err.status === 400 || err.status === 401) {
      // refresh token rejected (expired after 90 days, revoked or reused): user must authorize again
      this._authFailed = true;
      this.emit('auth:expired');
    } else {
      this._scheduleReconnect(); // network problem etc: retry with backoff
    }
  }

  _scheduleReconnect() {
    if (!this._rtWanted || this._authFailed || this._rtReconnectTimer) return;
    const delay = Math.min(30 * 1000, 1000 * 2 ** this._rtAttempt++);
    this._rtReconnectTimer = this.homey.setTimeout(() => {
      this._rtReconnectTimer = null;
      this._openSocket().catch(err => this.error(err.message));
    }, delay);
  }

  _closeSocket() {
    this.homey.clearTimeout(this._rtRenewTimer);
    if (this._ws) {
      const ws = this._ws;
      this._ws = null;
      ws.removeAllListeners('close');
      ws.on('error', () => {});
      try { ws.close(); } catch (err) { /* ignore */ }
    }
  }

  async onUninit() {
    this._rtWanted = false;
    this.homey.clearTimeout(this._rtReconnectTimer);
    this._closeSocket();
  }

};
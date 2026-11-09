'use strict';

const { OAuth2App } = require('homey-oauth2app');
const ThunderHomeClient = require('./lib/ThunderHomeClient');

module.exports = class ThunderHomeApp extends OAuth2App {

  static OAUTH2_CLIENT = ThunderHomeClient;
  static OAUTH2_DEBUG = false;
  static OAUTH2_MULTI_SESSION = false; // one app-level session
  static OAUTH2_DRIVERS = ['device'];

  async onOAuth2Init() {
    this.log('ThunderHome app initialized');
  }

};
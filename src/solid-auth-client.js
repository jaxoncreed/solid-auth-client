import {
  getClientAuthenticationWithDependencies,
  Session
} from '@inrupt/solid-client-authn-browser'
// @flow
import EventEmitter from 'events'
import { openIdpPopup, obtainSession } from './popup'

import { defaultStorage } from './storage'
import { toUrlString, currentUrlNoParams } from './url-util'

export type loginOptions = {
  callbackUri: string,
  clientName?: string,
  contacts?: Array<string>,
  logoUri?: string,
  popupUri: string,
  storage: AsyncStorage
}

export default class SolidAuthClient extends EventEmitter {
  async getAuthFetcher(storage) {
    let clientAuthentication
    if (storage) {
      const asyncStorage = storage

      clientAuthentication = getClientAuthenticationWithDependencies({
        secureStorage: {
          get: key => asyncStorage.getItem(key),
          set: (key, value) => asyncStorage.setItem(key, value),
          delete: key => asyncStorage.removeItem(key)
        }
      })
    } else {
      clientAuthentication = getClientAuthenticationWithDependencies({})
    }
    return new Session(
      {
        clientAuthentication
      },
      'default'
    )
  }

  async handleIncomingRedirect(storage?: AsyncStorage) {
    const authFetcher = await this.getAuthFetcher(storage || defaultStorage())

    const authCode =
      new URL(window.location.href).searchParams.get('code') ||
      // FIXME: Temporarily handle both autch code and implicit flow.
      // Should be either removved or refactored.
      new URL(window.location.href).searchParams.get('access_token')
    if (authCode) {
      await authFetcher.handleIncomingRedirect(new URL(window.location.href))
    }
  }

  async fetch(input: RequestInfo, options?: RequestOptions): Promise<Response> {
    const authFetcher = await this.getAuthFetcher()
    this.emit('request', toUrlString(input))
    // @ts-ignore TODO: reconcile the input type
    return authFetcher.fetch(input, options)
  }

  async login(idp: string, options: loginOptions): Promise<?Session> {
    options = { ...defaultLoginOptions(currentUrlNoParams()), ...options }
    const authFetcher = await this.getAuthFetcher(options.storage)
    await authFetcher.login({
      redirectUrl: options.callbackUri,
      oidcIssuer: idp
    })
  }

  async popupLogin(options: loginOptions): Promise<?Session> {
    options = { ...defaultLoginOptions(), ...options }
    if (!/https?:/.test(options.popupUri)) {
      options.popupUri = new URL(
        options.popupUri || '/.well-known/solid/login',
        window.location.href
      ).toString()
    }
    if (!options.callbackUri) {
      options.callbackUri = options.popupUri
    }
    const popup = openIdpPopup(options.popupUri)
    const session = await obtainSession(options.storage, popup, options)
    this.emit('login', session)
    this.emit('session', session)
    return session
  }

  async currentSession(storage?: AsyncStorage): Promise<?Session> {
    await this.handleIncomingRedirect(storage || defaultStorage())
    const authFetcher = await this.getAuthFetcher(storage || defaultStorage())
    if (authFetcher.info.isLoggedIn) {
      return {
        webId: authFetcher.info.webId,
        sessionKey: authFetcher.info.sessionId
      }
    }
    return null
  }

  async trackSession(
    callback: Function,
    storage?: AsyncStorage
  ): Promise<void> {
    /* eslint-disable standard/no-callback-literal */
    callback(await this.currentSession(storage || defaultStorage()))
    this.on('session', callback)
  }

  stopTrackSession(callback: Function): void {
    this.removeListener('session', callback)
  }

  async logout(storage?: AsyncStorage): Promise<void> {
    const authFetcher = await this.getAuthFetcher(storage || defaultStorage())
    if (authFetcher.info.isLoggedIn) {
      try {
        await authFetcher.logout()
        this.emit('logout')
        this.emit('session', null)
      } catch (err) {
        console.warn('Error logging out:')
        console.error(err)
      }
    }
  }
}

function defaultLoginOptions(url: ?string): loginOptions {
  return {
    callbackUri: url ? url.split('#')[0] : '',
    popupUri: '',
    storage: defaultStorage()
  }
}

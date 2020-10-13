// @flow
import React from 'react'
import auth from '../../src/'

const popupUri = process.env.POPUP_URI

export default class AuthButtons extends React.Component<Object, Object> {
  state: {
    loggedIn?: boolean
  }
  constructor(props: {}) {
    super(props)
    this.state = {}
    auth.trackSession(session => this.setState({ loggedIn: !!session }))
  }

  logout() {
    auth.logout()
  }

  login() {
    const idp = window.prompt(
      'What is the URL of your identity provider?',
      'http://localhost:8080'
    )
    if (idp) {
      auth.login(idp, {})
    }
  }

  popupLogin() {
    auth.popupLogin({
      popupUri
    })
  }

  render() {
    return this.state.loggedIn ? (
      <button onClick={this.logout}>Log out</button>
    ) : (
      <div>
        <button onClick={this.login}>Log in</button>
        <button onClick={this.popupLogin}>Log in via popup</button>
      </div>
    )
  }
}

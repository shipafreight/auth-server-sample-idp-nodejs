const dotenv = require('dotenv')
const assert = require('assert')
const express = require('express')
const jose = require('jose');
const path = require('path');

if (process.env.NODE_ENV === 'development') {
  dotenv.config()
}

const app = express()

app.use(express.urlencoded())
app.set('view engine', 'ejs')
app.set('views', path.resolve(__dirname, 'views'))

const CLIENT_ID = '4788d283-835d-4b57-8599-20d886d3d806'
const VALID_REDIRECT_URIS = [
  'http://localhost:3010/auth/',
  'https://auth-staging.shipafreightservices.com/auth/',
  'https://auth.shipafreight.com/auth/',
]

const signAndEncrypt = (payload) => {
  const signed = jose.JWS.sign(payload, process.env.SIGN_PRIVATE_KEY) // verify it's from partner
  const encrypted = jose.JWE.encrypt(signed, process.env.ENC_PUBLIC_KEY) // only SF can see the ID token (private key)
  return encrypted
}

const buildRedirectUri = (redirectUri, params) => {
  const hasQueryString = ~redirectUri.indexOf('?')
  const mergedParams = Object.keys(params).map(param => `${param}=${params[param]}`).join('&')

  if (hasQueryString) {
    return `${redirectUri}&${mergedParams}`
  }

  return `${redirectUri}?${mergedParams}`
}

const validateRequestParams = (req) => {
  assert(req.query.client_id, 'client_id query string param missing')
  assert(req.query.redirect_uri, 'redirect_uri query string param missing')
  assert(req.query.response_type, 'response_type query string param missing')

  // verify client_id (optional)
  assert(req.query.client_id === CLIENT_ID, 'invalid client_id')

  // verify response_type (optional)
  assert(req.query.response_type === 'id_token', 'invalid response_type: needs to be id_token')

  // verify issuer (optional)
  const validRedirectUri = VALID_REDIRECT_URIS.some(redirectUri => req.query.redirect_uri.match(redirectUri))
  assert(validRedirectUri, 'invalid redirect_uri')
}

/**
 * render login page
 */
app.get('/auth', (req, res, next) => {
  validateRequestParams(req)

  return res.render('login', {
    title: 'Login',
    clientId: req.query.client_id,
    responseType: req.query.response_type,
    redirectUri: encodeURIComponent(req.query.redirect_uri),
  })
})

/**
 * render login page
 */
app.get('/auth/register', (req, res, next) => {
  validateRequestParams(req)

  return res.render('register', {
    title: 'Register',
    clientId: req.query.client_id,
    responseType: req.query.response_type,
    redirectUri: encodeURIComponent(req.query.redirect_uri),
  })
})

/**
 * render decode id token page
 */
app.get('/auth/decode-token', (req, res, next) => {
  return res.render('decode-token', {
    title: 'Decode ID Token',
    payload: null,
    encryptedToken: null,
    signingPublicKey: null,
  })
})

app.post('/auth/decode-token', (req, res, next) => {
  const encryptedToken = req.body.id_token
  const signingPublicKey = req.body.sign_public_key

  let payload
  
  try {
    const decryptedToken = jose.JWE.decrypt(encryptedToken, process.env.ENC_PRIVATE_KEY).toString()
    payload = jose.JWS.verify(decryptedToken, signingPublicKey)
  } catch (err) {
    payload = 'Failed to decode the token'
  }

  return res.render('decode-token', {
    title: 'Decode ID Token',
    payload,
    encryptedToken,
    signingPublicKey,
  })
})

/**
 * example usage:
 * - http://localhost:4000/auth?client_id=4788d283-835d-4b57-8599-20d886d3d806&response_type=id_token&redirect_uri=http%3A%2F%2Flocalhost%3A3010%2Fauth%2FC8SIFKS6EygPq2aJT2IrJ
 */
app.post('/auth', (req, res, next) => {
  validateRequestParams(req)

  // perform login / registration

  const idTokenPayload = {
    email: req.body.email, // required
    firstName: req.body.firstName || 'Hamza', // optional
    lastName: req.body.lastName || 'Purra', // optional
    companyName: req.body.companyName || 'Hello World',
    // countryCode: CountryCode, // optional
    // phoneNumber: '+55 11 96413-2640' // optional
  }

  const idToken = signAndEncrypt(idTokenPayload)

  const redirectUri = buildRedirectUri(req.query.redirect_uri, {
    id_token: idToken,
  })

  res.redirect(302, redirectUri)
})

/**
 * redirect with error and error_description
 */
app.post('/auth/abort', (req, res, next) => {
  validateRequestParams(req)

  const redirectUri = buildRedirectUri(req.query.redirect_uri, {
    error: 'access_denied',
    error_description: encodeURIComponent('the user denied the request')
  })

  res.redirect(302, redirectUri)
})

const port = process.env.PORT || 4000

app.listen(port, () => {
  console.log(`shipafreight-test-idp is running on port ${port}`)
})

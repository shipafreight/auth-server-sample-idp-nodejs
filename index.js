const assert = require('assert')
const express = require('express')
const jose = require('jose');
const path = require('path');

const app = express()
app.use(express.urlencoded())
app.set('view engine', 'ejs')
app.set('views', path.resolve(__dirname, 'views'))

// sign with partner's private key (SF Auth Server will then use partner's public key)
const SIGNING_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEtwIBADANBgkqhkiG9w0BAQEFAASCBKEwggSdAgEAAoIBAACX9GOASGo5dt5W\nKzeoLmG1aSkfnC5Qq51TeYiHwNCiyCVg3yW7dU3Ixc+mUp1gZwxOpG5f8ucE1quo\nSfBvfZwPW2i4MShft3JCFIIODaVi4sGnhoiWK/X3jyQm0sHYPqRGvecdHcjZJnzc\n9cNUjGWKv+/D+GBgael3EutM4raGocv9Be8r1W0fKIb3U+GM+0M2WXNapsGrlwmJ\nYKZBTCqhNS8sVgRyGG47KlIaKrhkmuelB+LtGnOe41iPk67m1kiK43Ib9wMBMeu1\nW6FNWGTwH5LARrTO8yQLfnegwHcojrMsOi50rWg0aMgcc+mGtTH+6pI/9fosmjl8\nh+4dHgcCAwEAAQKB/0DHk/+lX3ud/E0Z4YFWPJtc+IYcS/ZiIxDqF9Vf0tICp0Sz\n/N78tCtqgQqz35mwdKO2H8PRxsDeT5HP66tsDjLR0kPr2P1tNE2NdqBNGvucFdi4\nVtRGa3adVFkksjThB6GM5dEY2H4SlVqRfzM1IzjSeIHACj4wCLKVozBE2nFiUdfN\nzGvq73+Iq++WfuyNOjUZkEyHBbz5HFhv/AgsmcoHfPqSPXtVyS/zEkLU0CGaRP7W\nnSYLt8qeUnFSr/xmN0n015euLhjaLw4H7DhnEG9V2UxfEhVllRe3bqKXMTHsCEjO\nqnxL32wJckr6GDFcAfhmUtKckGwjIGxDd0xmuQKBgA0vXWdNfCI9ZZtl8IOVuSRR\nYq+/zZB+zg6MsMOK/AMOdRwrsypDAKOx2Ba369c4fjdO9O5ZX1TU01uyE8/K07qr\naa87LT7X0xVfy3GZiujGPwFsUSb8zBfWrEWl254cPsj4LcLqrxERHYER3tHCbNm2\nYYA9uqcyf5MpRdyXu5BFAoGAC4ZY+kRR3pGNSxaY0biNlj+InxsB9wXQREuJNwA9\nJwGhhp5/npoXv+JxUC9Vj4jk355ultRvexwX8AX/+8WplkUn6PI3OhTG2A4pRnjA\nnoHtFfiZgfoIvgNs3qdwCBGnx5kHZmu43wCViVdKr9cmuFl/fKUERfu95CzjvNVQ\nl9sCgYAFUWJJ5R25LaxKpi4A1KWs+UplemXt7scrZSFybR9CGFWxvApydD3QyE1Q\ntHPiBX4azrTJYbCqpYBuDoAhIjyNoM9qhuKz4xbXGyESO4ykYDlPWKHOqM2km8g1\n+zR+LARCyJ6kbEWaC54rzcpiLhn7Ia1nrP4Yq6x67X2pAGX9RQKBgAPgG4+c5cLo\nQxEa+iyb2NDLcI/ALzr3837jv7KFHAs/2yc/qT6WJqJZ7Sy/ng/0QrKHvjxuF0bY\nvZvzCI+LemmTu8XznWqkjfEdYffWpz8mBam7vTMd906eLD/7Igs0lKzj4r8oPjSP\nJ7nVZsIWoWigf+RUQUmfS82s4rAfM0i9AoGABmwUJJPG5DRErwmknNeaLGgsSIC2\nUqgqfueSjS4yKNjUP+bg27NANKxEyBBaB/MJPZQl5cR/SxcbOKQM4cdQqn+eXZD8\ndltW/GcP3K+nrM0G5OUGfr1p1V9/d4iDJz/l9buFwmTnmWwb7HjXc7Ie3qnz/puZ\nQVDwcNwRAxox0T4=\n-----END PRIVATE KEY-----'

// encrypt using SF Auth Server's public key
const ENCRYPTION_KEY = '-----BEGIN PUBLIC KEY-----\nMIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQAAmSW8tmE1zJwyVbi2imOe\nVfTnNuyyA7QxX94Iu0S2kyK9CbqlMDWoObk8ZjWh7WZP8v0o3T/ZspMF8nyuVvHF\nudhP9yAtaN5etvxFd3imYVt+tt2lA/vBToT+Yg5Vd5W5yOqbSTgb/sWl/2piU1Pa\nwlWX/aJbyS/MiNRkFUA/k+v1Y9BQmNVgxQJyDwVuFKDiMiy/yhdpgrA/JcLvXtIy\nG8OZ0aAhEo8sF/OrqfVKtGdbmrOpsz0j7YQfyZKPjw2AnyuPRk3gMPhzmPWPM4zS\nAMHRIJxSJnHYU+63jtFd2zFLp4+shZGDywYbeDhjpj5kw4TDcV/QRmwiZ2dvLbhT\nAgMBAAE=\n-----END PUBLIC KEY-----'

const CLIENT_ID = '4788d283-835d-4b57-8599-20d886d3d806'
const VALID_REDIRECT_URIS = [
  'http://localhost:3010/auth/',
  'https://auth-staging.shipafreightservices.com/auth/',
  'https://auth.shipafreight.com/auth/',
]

const signAndEncrypt = (payload) => {
  const signed = jose.JWS.sign(payload, SIGNING_KEY) // verify it's from partner
  const encrypted = jose.JWE.encrypt(signed, ENCRYPTION_KEY) // only SF can see the ID token (private key)
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

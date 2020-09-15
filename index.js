const assert = require('assert')
const express = require('express')
const jose = require('jose');
const path = require('path');

const app = express()
app.use(express.urlencoded())
app.set('view engine', 'ejs')
app.set('views', path.resolve(__dirname, 'views'))

// sign with partner's private key (SF Auth Server will then use partner's public key)
const SIGNING_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbjm9hnKyaZu+I\n49y73FFdb3+3Xuh8xEvx72cJzFshyMiaT0ExshUVZEhLKuRXrM7SJsq1p3LYbGeb\neKwQ63H1X48oVHKVcuOsttgMUhFoKXY6xyp+XncJfoqrS36YePZCW2LdM1OU5AZV\nH4qbW+fJvfymv/xi3L/MuS/yVf0OxMU+PbqIO1gjQK24Rc6hZq5nCQ+UNQEKBhfU\njU7MVOy60dDciDaskJ2/Bpx09WXU7R6GIHlBb+/BEYsrCd7bmEREhYYdavMIPBNU\nJIb0zYTX55MbdIudDYYnkcXJ6Dy8eieMmQBKoyF8ZlHLjEQCrWsYD4BKGcbcpzQy\nUdNMZYo/AgMBAAECggEAS4j2UtvHGhu93xedslf6+i1JADo7u+kAw8x8Y4eV9sqQ\nEV6g7Er7K+/jW1D3XB6MzQohhVuFjGXHQ1rBv9Rw0V098D8VaMss/xesvphhereB\nAHnS6cTwKSkK5iHD/Qroli3Alp946umEMDb4xbhZxzOAv5GfcBfIONOhZjslI7X1\nOkVvRSkWY346wyJs14gS7iKtigV9hM2ZvNK1AVtpCufPmNOiy0xRp5A2KMTfWTgb\n2rgW58ucVSJccdULucNNCA43/liL7GQSMko8Ud7WzbGCIa3FPx8f1RgV1YynbFHv\nrrlahd50D7tTS/68+Xr8t7qbffs223trFq/bJDshaQKBgQD8235p3B022aqU9ahV\ntccivduB4CS1ZHmbgFYeJfcyu08TruGclZnhBlAo5yLurqX6Mg+v4emcDruwQCeM\n3zp0OmkUjuEkw9qUcILLW71SwDO+0zwPx4Q5Nk1+Ptk5QOf0QUnnYGEUb28/Izt7\nV2PldB/iZz85Zgv9h5x2d5RdbQKBgQDeSP0hwCdPKaEENIol436i4KWgXIvVOHI9\ng3Rsp8TxGIOVtzms5Izt4s3AyNcVz2Q1HJQz6NuJp213C4V7rhpFCf6mZGWyXvMM\nTMbdcXJ4AT2XDCuNY4O/usG+HigD+4njoGhBT28vJRC+fHc9i5kz3Dyya0DdqRVU\n0m/a4hNW2wKBgHJZuTOajcOucExpRDVuvZ3iipCTk0ZNKAnA4jFELiTNPJfEMNel\neC+hsUKuNMgIR5t8ZEfAPOuMZijw+nHkygSiHb9kVkFQKVuT/jKFTHtN3Jjh4nmo\nWw2clzMOrSINTljR5eAzX/Pj6UV+Y3oGLXEpMPosgxUsJyQC3ildLsWJAoGAfVCi\nvGtK/fsXFnrUQ0X8t7B0T3K9NoirBvjcIwF2KwHJ9Ralwk3bEaWin4PaliYkdTjW\naGlnkzQ7pzhsmWxuzOs0j/PbzXJwDUgfeOojQXpZkZU/3Gb0+Js97IOtxYkClLxy\n6hbxNJ/tz6X1x1GzHiSUZ3XFzPEs4HP+sWRwyK8CgYEAt8gORVgUi4Q2qt/7IfRm\n48ABtZaI4mzCEo3ys0WS9FUJL22hXTvstNZitZJHLuGuztoOKg6bguY7Do8Lhr1O\nEMOQlMxW384UzoPHNEvt7k+xuWJcd59Vb7xoDwVwnNLj7XYO70TlKAo16fg3gKx+\nG8vvRszxv3HYntDVMFF+Y5Y=\n-----END PRIVATE KEY-----'

// encrypt using SF Auth Server's public key
const ENCRYPTION_KEY = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmxwa3RPoo9EBjD8MLTz8\nuA6yanpRRCgzspeeCn9ClDfLBgRd3/jZUnRQ+IkScubabC6GDwcg/GaLa+qB/Ngf\n8XRlHgTG/KKpX7EiXVC9dB2J1rDSaax3XHH01OBx21ziBfaHNifatptiMWjDLFUq\nTH27jSbi2qMVH0EiDG3WRSc1f9VpK2BAU5xCrF45HjMQjUzvR3XxBETQXFKzYSe1\nAFmKIeUnO5Ic1JtjWtQlfH7+7+41vETdSP6VmqhT1brkWxzJBB3H42jJym9KEJW4\nQzQ0y7EyZWlp1Xcc9AD85LdDcd1ulm0AUFEKvoEn3EzKlHCiz+cT31LaJQ8rfpcF\nEwIDAQAB\n-----END PUBLIC KEY-----'

const CLIENT_ID = '4788d283-835d-4b57-8599-20d886d3d806'
const VALID_REDIRECT_URIS = [
  'http://localhost:3010/auth/'
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

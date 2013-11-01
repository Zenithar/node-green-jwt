# Node
crypto  = require 'crypto'

# Lib
ju      = require '../utils'
jwa     = require '../jwa'
jws     = require '../jws'

#
# Supports the following JSON Web Algorithms (JWAs)
#   * JWSAlgorithm.HS256
#   * JWSAlgorithm.HS384
#   * JWSAlgorithm.HS512
#
class CryptoMacProvider extends jws.BaseJWSProvider
  
  getAlgorithmName: (alg) ->
    return "sha256" if alg == 'HS256'
    return "sha384" if alg == 'HS384'
    return "sha512" if alg == 'HS512'
    throw new Error "Unsupported HMAC algorithm, must be HS256, HS384 or HS512"

  constructor: (@sharedSecret) ->
    throw new Error "The shared secret must not be null" unless @sharedSecret?
    algs = []
    algs.push jwa.JWSAlgorithm.parse('HS256')
    algs.push jwa.JWSAlgorithm.parse('HS384')
    algs.push jwa.JWSAlgorithm.parse('HS512')
    super(algs)

class CryptoMacSigner extends jwa.JWSSigner

  constructor: (@sharedSecret) ->
    @provider = new CryptoMacProvider(sharedSecret)

  sign: (header, content)->
    throw new Error "Invalid header : must not be null !" unless header?
    throw new Error "Invalid header : alg missing !" unless header.alg?
    throw new Error "Invalid content : must not be null !" unless content?

    alg = @provider.getAlgorithmName header.alg
    hmac = crypto.createHmac(alg, @sharedSecret).update(content).digest()
    ju.base64urlEncode(hmac)

class CryptoMacVerifier extends jwa.JWSVerifier

  constructor: (@sharedSecret) ->
    @provider = new CryptoMacProvider(sharedSecret)

  verify: (header, content, givenSignature) ->
    throw new Error "Invalid header : must not be null !" unless header?
    throw new Error "Invalid content : must not be null !" unless content?
    throw new Error "Invalid signature : must not be null !" unless givenSignature?
    throw new Error "Invalid header : alg missing !" unless header.alg?

    alg = @provider.getAlgorithmName header.alg
    hmac = crypto.createHmac(alg, @sharedSecret).update(content).digest()
    sig = ju.base64urlEncode(hmac)
    return sig == givenSignature

module.exports = 
  MacSigner: CryptoMacSigner
  MacVerifier: CryptoMacVerifier

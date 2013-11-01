# Lib
jwa     = require "./jwa"

class BaseJWEProvider extends jwa.JWEAlgorithmProvider
	constructor: (@algs, @encs) ->
		throw new Error "The supported JWE algorithm set must not be null" unless @algs?
		throw new Error "The supported encryption methods must not be null" unless @encs?
		
  supportedAlgorithms: ->
    @algs

  supportedEncryptionMethods: ->
    @encs

module.exports = 
  spec_version : "draft-ietf-jose-json-web-encryption-17"
  BaseJWEProvider: BaseJWEProvider


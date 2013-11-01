# Lib
jwa     = require "./jwa"

class BaseJWSProvider extends jwa.JWSAlgorithmProvider
	constructor: (@algs) ->
		throw new Error "The supported JWS algorithm set must not be null" unless @algs?

	supportedAlgorithms: ->
		@algs

module.exports =
	spec_version : "draft-ietf-jose-json-web-signature-17"
	BaseJWSProvider: BaseJWSProvider
# Tests
should = require "should"

# Self
jwa	   = require "../lib/jwa"

describe 'JWA - Module', ->

	( (exp) =>
		it "should export #{exp}", ->
			should.exist jwa[exp]
	)(exp) for exp in ["spec_version", "Requirement", "JWSAlgorithm","JWSAlgorithmProvider","JWSSigner","JWSVerifier","JWEAlgorithm","JWEAlgorithmProvider","JWEEncrypter","JWEDecrypter","EncryptionMethod"]

describe 'JWA - Signers', ->

	it "should supports `NONE`", ->
    algorithm = jwa.JWSAlgorithm.parse 'NONE' 
    should.exist algorithm

	it "should throw an error if an invalid algorithm is provided", ->
    should.not.exist jwa.JWSAlgorithm.parse("HS124")

	( (alg) => 
  	it "should supports `#{alg}`", ->
    	algorithm = jwa.JWSAlgorithm.parse(alg)
    	should.exist algorithm

  )(alg) for alg in ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

describe 'JWA - Encrypters', ->

	it "should supports `NONE`", ->
    algorithm = jwa.JWEAlgorithm.parse 'NONE' 
    should.exist algorithm

	it "should throw an error if an invalid algorithm is provided", ->
    should.not.exist jwa.JWEAlgorithm.parse("HS124")

	( (alg) => 
  	it "should supports `#{alg}`", ->
    	algorithm = jwa.JWEAlgorithm.parse(alg)
    	should.exist algorithm

  )(alg) for alg in ["RSA1_5", "RSA-OAEP", "A128KW", "A192KW", "A256KW", "DIR", "ECDH_ES", "ECDH_ES_A128KW", "ECDH_ES_A192KW", "ECDH_ES_A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "PBES2_HS256_A128KW", "PBES2_HS256_A192KW", "PBES2_HS256_A256KW"]

describe 'JWA - Encryption Methods', ->

	it "should supports `NONE`", ->
    algorithm = jwa.EncryptionMethod.parse 'NONE' 
    should.exist algorithm

	it "should throw an error if an invalid algorithm is provided", ->
    should.not.exist jwa.EncryptionMethod.parse("HS124")

	( (alg) => 
  	it "should supports `#{alg}`", ->
    	algorithm = jwa.EncryptionMethod.parse(alg)
    	should.exist algorithm

  )(alg) for alg in ['A128CBC-HS256','A192CBC-HS384','A256CBC-HS512','A128GCM','A192GCM','A256GCM']


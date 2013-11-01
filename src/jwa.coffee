#
# Enumeration of JOSE algorithm implementation requirements. Refers to the 
# requirement levels defined in RFC 2119.
#
Requirement =

  # The implementation of the algorithm is required
  REQUIRED: "REQUIRED"

  # The implementation of the algorithm is recommended
  RECOMMENDED: "RECOMMENDED"

  # The implementation of the algorithm is optional
  OPTIONAL: "OPTIONAL"

#
# Shared base class for Signing / Encryption algorithms
#
class Algorithm
  constructor: (@name = "NONE", @requirement = Requirement.REQUIRED) ->

#
# Base class for Signing Algorithm
#
class JWSAlgorithm extends Algorithm
  algorithms =
    'NONE'  : new JWSAlgorithm("NONE", Requirement.REQUIRED)

    # HMAC using SHA-256 hash algorithm (required).
    'HS256' : new JWSAlgorithm("HS256", Requirement.REQUIRED)
    
    # HMAC using SHA-384 hash algorithm (optional).
    'HS384' : new JWSAlgorithm("HS384", Requirement.OPTIONAL)
    
    # HMAC using SHA-512 hash algorithm (optional).
    'HS512' : new JWSAlgorithm("HS512", Requirement.OPTIONAL)
    
    # RSASSA-PKCS-v1_5 using SHA-256 hash algorithm (recommended).
    'RS256' : new JWSAlgorithm("RS256", Requirement.RECOMMENDED)
    
    # RSASSA-PKCS-v1_5 using SHA-384 hash algorithm (optional).
    'RS384' : new JWSAlgorithm("RS384", Requirement.OPTIONAL)
    
    # RSASSA-PKCS-v1_5 using SHA-512 hash algorithm (optional).
    'RS512' : new JWSAlgorithm("RS512", Requirement.OPTIONAL)
    
    # ECDSA using P-256 curve and SHA-256 hash algorithm (recommended).
    'ES256' : new JWSAlgorithm("ES256", Requirement.RECOMMENDED)
    
    # ECDSA using P-384 curve and SHA-384 hash algorithm (optional).
    'ES384' : new JWSAlgorithm("ES384", Requirement.OPTIONAL)
    
    # ECDSA using P-521 curve and SHA-512 hash algorithm (optional).
    'ES512' : new JWSAlgorithm("ES512", Requirement.OPTIONAL)
    
    # RSASSA-PSS using SHA-256 hash algorithm and MGF1 mask generation function with SHA-256 (optional).
    'PS256' : new JWSAlgorithm("PS256", Requirement.OPTIONAL)
    
    # RSASSA-PSS using SHA-384 hash algorithm and MGF1 mask generation function with SHA-384 (optional).
    'PS384' : new JWSAlgorithm("PS384", Requirement.OPTIONAL)
    
    # RSASSA-PSS using SHA-512 hash algorithm and MGF1 mask generation function with SHA-512 (optional).
    'PS512' : new JWSAlgorithm("PS512", Requirement.OPTIONAL)
 
  @parse: (alg) ->
    return algorithms[alg] if algorithms[alg]?
    return null

#
# Base class for JWS Signing provider
#
class JWSAlgorithmProvider 
  supportedAlgorithms: () ->
    throw new Error("Must be implemented by inheritance.")

#
# Base class for Signer
# 
class JWSSigner extends JWSAlgorithmProvider
  sign: (header, content) ->
    throw new Error("Must be implemented by inheritance.")

#
# Base class for Verifier
# 
class JWSVerifier extends JWSAlgorithmProvider
  verify: (header, content, givenSignature) ->
    throw new Error("Must be implemented by inheritance.")

#
# Base class for Encryption Algorithm
#
class JWEAlgorithm extends Algorithm
  algorithms =
    'NONE'  : new JWEAlgorithm("NONE", Requirement.REQUIRED)
    
    # RSAES-PKCS1-V1_5 (RFC 3447) (required).
    'RSA1_5'  : new JWEAlgorithm("RSA1_5", Requirement.REQUIRED)
    
    # RSAES using Optimal Assymetric Encryption Padding (OAEP) (RFC 3447),
    # with the default parameters specified by RFC 3447 in section A.2.1
    # (recommended).
    'RSA-OAEP': new JWEAlgorithm("RSA-OAEP", Requirement.RECOMMENDED)

    # Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) 
    # using 128 bit keys (recommended).
    'A128KW'  : new JWEAlgorithm("A128KW", Requirement.RECOMMENDED)

    # Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
    # using 192 bit keys (optional).
    'A192KW'  : new JWEAlgorithm("A192KW", Requirement.OPTIONAL)
    
    # Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394) 
    # using 256 bit keys (recommended).
    'A256KW'  : new JWEAlgorithm("A256KW", Requirement.RECOMMENDED)

    # Direct use of a shared symmetric key as the Content Encryption Key 
    # (CEK) for the block encryption step (rather than using the symmetric
    # key to wrap the CEK) (recommended).
    'DIR'     : new JWEAlgorithm("DIR", Requirement.RECOMMENDED)

    # Elliptic Curve Diffie-Hellman Ephemeral Static (RFC 6090) key 
    # agreement using the Concat KDF, as defined in section 5.8.1 of
    # NIST.800-56A, with the agreed-upon key being used directly as the 
    # Content Encryption Key (CEK) (rather than being used to wrap the 
    # CEK) (recommended).
    'ECDH_ES' : new JWEAlgorithm("ECDH_ES", Requirement.RECOMMENDED)

    # Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
    # "ECDH-ES", but where the agreed-upon key is used to wrap the Content
    # Encryption Key (CEK) with the "A128KW" function (rather than being 
    # used directly as the CEK) (recommended).
    'ECDH_ES_A128KW': new JWEAlgorithm("ECDH_ES+A128KW", Requirement.RECOMMENDED)

    # Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
    # "ECDH-ES", but where the agreed-upon key is used to wrap the Content
    # Encryption Key (CEK) with the "A192KW" function (rather than being 
    # used directly as the CEK) (optional).
    'ECDH_ES_A192KW': new JWEAlgorithm("ECDH_ES+A192KW", Requirement.OPTIONAL)

    # Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
    # "ECDH-ES", but where the agreed-upon key is used to wrap the Content
    # Encryption Key (CEK) with the "A256KW" function (rather than being 
    # used directly as the CEK) (recommended).   
    'ECDH_ES_A256KW': new JWEAlgorithm("ECDH_ES+A256KW", Requirement.RECOMMENDED)

    # AES in Galois/Counter Mode (GCM) (NIST.800-38D) 128 bit keys
    # (optional).
    'A128GCMKW' : new JWEAlgorithm("A128GCMKW", Requirement.OPTIONAL)

    # AES in Galois/Counter Mode (GCM) (NIST.800-38D) 192 bit keys
    # (optional).
    'A192GCMKW' : new JWEAlgorithm("A192GCMKW", Requirement.OPTIONAL)
    
    # AES in Galois/Counter Mode (GCM) (NIST.800-38D) 256 bit keys
    # (optional).
    'A256GCMKW' : new JWEAlgorithm("A256GCMKW", Requirement.OPTIONAL)

    # PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
    # (RFC 3394) using 128 bit keys for the encryption scheme (optional).
    'PBES2_HS256_A128KW': new JWEAlgorithm("PBES2-HS256+A128KW", Requirement.OPTIONAL)

    # PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
    # (RFC 3394) using 192 bit keys for the encryption scheme (optional).
    'PBES2_HS256_A192KW': new JWEAlgorithm("PBES2-HS256+A192KW", Requirement.OPTIONAL)

    # PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
    # (RFC 3394) using 256 bit keys for the encryption scheme (optional).
    'PBES2_HS256_A256KW': new JWEAlgorithm("PBES2-HS256+A256KW", Requirement.OPTIONAL)

  @parse: (alg) ->
    return algorithms[alg] if algorithms[alg]?
    return null

class EncryptionMethod extends Algorithm
  algorithms =
    'NONE' : new EncryptionMethod("NONE", Requirement.REQUIRED, 0)

    # AES_128_CBC_HMAC_SHA_256 authenticated encryption using a 128 bit
    # key (required).
    'A128CBC-HS256': new EncryptionMethod("A128CBC-HS256", Requirement.REQUIRED, 256)

    # AES_192_CBC_HMAC_SHA_384 authenticated encryption using a 384 bit
    # key (optional).
    'A192CBC-HS384': new EncryptionMethod("A192CBC-HS384", Requirement.OPTIONAL, 384)

    # AES_256_CBC_HMAC_SHA_512 authenticated encryption using a 512 bit
    # key (required).
    'A256CBC-HS512': new EncryptionMethod("A256CBC-HS512", Requirement.REQUIRED, 512)

    # AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 128 bit key 
    # (recommended).
    'A128GCM': new EncryptionMethod("A128GCM", Requirement.RECOMMENDED, 128)

    # AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 192 bit key 
    # (recommended).
    'A192GCM': new EncryptionMethod("A192GCM", Requirement.OPTIONAL, 192)

    # AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 256 bit key 
    # (recommended).
    'A256GCM': new EncryptionMethod("A256GCM", Requirement.OPTIONAL, 256)

  constructor: (@name, @requirement, @cekBitLength) ->
    super(@name, @requirement)

  @parse: (alg) ->
    return algorithms[alg] if algorithms[alg]?
    return null

#
# Base interface for Algorithm Provider
#
class JWEAlgorithmProvider
  supportedAlgorithms: ->
    throw new Error("Must be implemented by inheritance.")

  supportedEncryptionMethods: ->
    throw new Error("Must be implemented by inheritance.")

#
# Base interface for Decrypter
#
class JWEDecrypter extends JWEAlgorithmProvider
  decrypt: (header, encryptedKey, iv, cipherText, authTag) -> 
    throw new Error("Must be implemented by inheritance.")

#
# Base interface for Encrypter 
#
class JWEEncrypter extends JWEAlgorithmProvider
  encrypt: (header, clearText) ->
    throw new Error("Must be implemented by inheritance.")

##// -- exports
module.exports = 
  spec_version: "draft-ietf-jose-json-web-algorithms-17"
  Requirement: Requirement
  JWSAlgorithm: JWSAlgorithm
  JWSAlgorithmProvider: JWSAlgorithmProvider
  JWSSigner: JWSSigner
  JWSVerifier: JWSVerifier
  JWEAlgorithm: JWEAlgorithm
  JWEAlgorithmProvider: JWEAlgorithmProvider
  JWEEncrypter: JWEEncrypter
  JWEDecrypter:  JWEDecrypter
  EncryptionMethod: EncryptionMethod




# Tests
should = require "should"

# Self
signer = require "../lib/crypto/signer-provider"

describe "Crypto Node", ->

  describe "Module", ->

    it "should declare a MacSigner", ->
      should.exist signer
      should.exist signer.MacSigner

    it "should declare a MacVerifier", ->
      should.exist signer
      should.exist signer.MacVerifier

  describe "Signer Provider", ->

    describe "when using MacSigner", ->

      ( (alg) =>
        it "should support #{alg}", ->
          s = new signer.MacSigner "toto"
          sig = s.sign {alg: alg}, "pouet"
          should(sig).equal fixtures.macsigner[alg]
          sig = s.sign {alg: alg}, "poue"
          should(sig).not.equal(fixtures.macsigner[alg])

      )(alg) for alg in ['HS256', 'HS384', 'HS512']

    describe "when using MacVerifier", ->

      ( (alg) =>
        it "should support #{alg}", ->
          s = new signer.MacVerifier "toto"
          valid = s.verify {alg: alg}, "pouet", fixtures.macsigner[alg]
          should(valid).be.ok

      )(alg) for alg in ['HS256', 'HS384', 'HS512']

fixtures =
  macsigner:
    'HS256': "gBNzGjEEef_IL2tfgBR0TXfUkmfCwDJq-Dq-pCQHjwI"
    'HS384': "L58ywgkCXuvWoT5B_JKFkd8jFYBtV8bjD3acK7vJc-vTJnF181TErgZM8jqGEPcF"
    'HS512': "Lkk1YajymDGdLT8TsW-Ib8nba_QTBLpnEs5ri40eDlG20NHhhiBHk7_pQmhXxVBiwkKidn7CXsbsiGuUoFhpgQ"
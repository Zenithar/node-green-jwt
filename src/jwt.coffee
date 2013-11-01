# Node
crypto  = require "crypto"
qstring = require "querystring"
# Lib
jws = require "./jws"
ju  = require "./utils"

# version of the specification we are based on. 
module.exports.spec_version = "draft-jones-json-web-token-10"
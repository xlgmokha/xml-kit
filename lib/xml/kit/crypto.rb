require 'xml/kit/crypto/oaep_cipher'
require 'xml/kit/crypto/rsa_cipher'
require 'xml/kit/crypto/symmetric_cipher'
require 'xml/kit/crypto/unknown_cipher'

module Xml
  module Kit
    module Crypto
      CIPHERS = [ SymmetricCipher, RsaCipher, OaepCipher, UnknownCipher ]

      # @!visibility private
      def self.cipher_for(algorithm, key)
        CIPHERS.find { |x| x.matches?(algorithm) }.new(algorithm, key)
      end
    end
  end
end

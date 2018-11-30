# frozen_string_literal: true

require 'xml/kit/crypto/oaep_cipher'
require 'xml/kit/crypto/rsa_cipher'
require 'xml/kit/crypto/symmetric_cipher'
require 'xml/kit/crypto/unknown_cipher'

module Xml
  module Kit
    module Crypto
      CIPHERS = [SymmetricCipher, RsaCipher, OaepCipher, UnknownCipher].freeze

      # @!visibility private
      def self.cipher_for(algorithm, key)
        CIPHERS.find { |x| x.matches?(algorithm) }.new(algorithm, key)
      end

      def self.cipher_registry(&block)
        BlockRegistry.new(&block)
      end

      class BlockRegistry
        def initialize(&factory)
          @factory = factory
        end

        def cipher_for(algorithm, key)
          @factory.call(algorithm, key)
        end
      end
    end
  end
end

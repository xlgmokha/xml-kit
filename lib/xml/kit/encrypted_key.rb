# frozen_string_literal: true

require 'xml/kit/templatable'

module Xml
  module Kit
    class EncryptedKey
      include ::Xml::Kit::Templatable
      DEFAULT_ALGORITHM = ::Xml::Kit::Crypto::RsaCipher::ALGORITHM

      attr_reader :id, :algorithm
      attr_reader :public_key, :key
      attr_accessor :key_info

      def initialize(id: Id.generate, public_key:, key:, key_info: nil, algorithm: DEFAULT_ALGORITHM)
        @id = id
        @algorithm = algorithm
        @public_key = public_key
        @key = key
        @key_info = key_info
      end

      def cipher_value
        asymmetric_cipher = asymmetric(algorithm, public_key)
        Base64.strict_encode64(asymmetric_cipher.encrypt(key))
      end

      private

      def asymmetric(algorithm, public_key)
        return algorithm unless algorithm.is_a?(String)

        ::Xml::Kit::Crypto.cipher_for(algorithm, public_key)
      end
    end
  end
end

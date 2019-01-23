# frozen_string_literal: true

module Xml
  module Kit
    class Encryption
      attr_reader :asymmetric_algorithm
      attr_reader :asymmetric_cipher_value
      attr_reader :symmetric_algorithm
      attr_reader :symmetric_cipher_value
      attr_reader :key_info

      def initialize(
        raw_xml,
        public_key,
        symmetric_algorithm: ::Xml::Kit::Crypto::SymmetricCipher::DEFAULT_ALGORITHM,
        asymmetric_algorithm: ::Xml::Kit::Crypto::RsaCipher::ALGORITHM,
        key_info: nil
      )
        @symmetric_algorithm = symmetric_algorithm
        symmetric_cipher = symmetric(symmetric_algorithm)
        @symmetric_cipher_value = Base64.strict_encode64(symmetric_cipher.encrypt(raw_xml))

        if key_info
          @key_info = key_info
        else
          @key_info = KeyInfo.new
          @key_info.encrypted_key = EncryptedKey.new(public_key: public_key, key: symmetric_cipher.key, algorithm: asymmetric_algorithm)

          @asymmetric_algorithm = asymmetric_algorithm
          @asymmetric_cipher_value = @key_info.encrypted_key.cipher_value
        end
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end

      def render(model, options)
        ::Xml::Kit::Template.new(model).to_xml(options)
      end

      private

      def symmetric(algorithm)
        return algorithm unless algorithm.is_a?(String)

        ::Xml::Kit::Crypto::SymmetricCipher.new(algorithm)
      end
    end
  end
end

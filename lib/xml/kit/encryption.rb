# frozen_string_literal: true

module Xml
  module Kit
    class Encryption
      attr_reader :asymmetric_algorithm
      attr_reader :asymmetric_cipher_value
      attr_reader :symmetric_algorithm
      attr_reader :symmetric_cipher_value

      def initialize(
        raw_xml,
        public_key,
        symmetric_algorithm: ::Xml::Kit::Crypto::SymmetricCipher::DEFAULT_ALGORITHM,
        asymmetric_algorithm: ::Xml::Kit::Crypto::RsaCipher::ALGORITHM
      )
        @symmetric_algorithm = symmetric_algorithm
        symmetric_cipher = symmetric(symmetric_algorithm)
        @symmetric_cipher_value = Base64.strict_encode64(symmetric_cipher.encrypt(raw_xml))

        @asymmetric_algorithm = asymmetric_algorithm
        asymmetric_cipher = asymmetric(asymmetric_algorithm, public_key)
        @asymmetric_cipher_value = Base64.strict_encode64(asymmetric_cipher.encrypt(symmetric_cipher.key))
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end

      private

      def symmetric(algorithm)
        return algorithm unless algorithm.is_a?(String)

        ::Xml::Kit::Crypto::SymmetricCipher.new(algorithm)
      end

      def asymmetric(algorithm, public_key)
        return algorithm unless algorithm.is_a?(String)

        ::Xml::Kit::Crypto.cipher_for(algorithm, public_key)
      end
    end
  end
end

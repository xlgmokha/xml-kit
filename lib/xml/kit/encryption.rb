# frozen_string_literal: true

module Xml
  module Kit
    class Encryption < EncryptedData
      attr_reader :asymmetric_algorithm
      attr_reader :symmetric_algorithm
      attr_reader :symmetric_cipher_value
      attr_reader :key_info

      def initialize(
        raw_xml,
        public_key,
        symmetric_algorithm: Crypto::SymmetricCipher::DEFAULT_ALGORITHM,
        asymmetric_algorithm: Crypto::RsaCipher::ALGORITHM,
        key_info: nil
      )
        @symmetric_algorithm = symmetric_algorithm
        @asymmetric_algorithm = asymmetric_algorithm
        Xml::Kit.deprecate('Encryption is deprecated. Use EncryptedData.')
        super(raw_xml,
          symmetric_cipher: symmetric(symmetric_algorithm),
          asymmetric_cipher: asymmetric(asymmetric_algorithm, public_key),
          key_info: key_info
        )
      end

      def template_path
        Template::TEMPLATES_DIR.join('encrypted_data.builder')
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

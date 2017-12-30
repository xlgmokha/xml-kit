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
        asymmetric_algorithm: "#{::Xml::Kit::Namespaces::XMLENC}rsa-1_5"
      )
        @symmetric_algorithm = symmetric_algorithm
        @symmetric_cipher_value = Base64.encode64(symmetric_cipher.encrypt(raw_xml))

        @asymmetric_algorithm = asymmetric_algorithm
        @asymmetric_cipher_value = Base64.encode64(public_key.public_encrypt(symmetric_cipher.key))
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end

      private

      def symmetric_cipher
        @symmetric_cipher ||= ::Xml::Kit::Crypto::SymmetricCipher.new(
          symmetric_algorithm
        )
      end
    end
  end
end

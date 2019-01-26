# frozen_string_literal: true

module Xml
  module Kit
    class EncryptedData
      attr_reader :key_info
      attr_reader :symmetric_cipher
      attr_reader :symmetric_cipher_value

      def initialize(
        raw_xml,
        symmetric_cipher:,
        asymmetric_cipher:,
        key_info: nil
      )
        @symmetric_cipher = symmetric_cipher
        @symmetric_cipher_value = Base64.strict_encode64(
          symmetric_cipher.encrypt(raw_xml)
        )
        @key_info = key_info || create_key_info_for(
          symmetric_cipher,
          asymmetric_cipher
        )
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end

      def render(model, options)
        ::Xml::Kit::Template.new(model).to_xml(options)
      end

      private

      def create_key_info_for(symmetric_cipher, asymmetric_cipher)
        KeyInfo.new do |x|
          x.encrypted_key = EncryptedKey.new(
            asymmetric_cipher: asymmetric_cipher,
            symmetric_cipher: symmetric_cipher
          )
        end
      end
    end
  end
end

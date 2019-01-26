# frozen_string_literal: true

require 'xml/kit/templatable'

module Xml
  module Kit
    # An implementation of the EncryptedKey element.
    # https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedKey
    #
    # @since 0.3.0
    class EncryptedKey
      include ::Xml::Kit::Templatable
      attr_reader :id
      attr_reader :asymmetric_cipher, :symmetric_cipher
      attr_accessor :key_info

      def initialize(
        id: Id.generate,
        asymmetric_cipher:,
        symmetric_cipher:,
        key_info: nil
      )
        @id = id
        @asymmetric_cipher = asymmetric_cipher
        @symmetric_cipher = symmetric_cipher
        @key_info = key_info
      end

      def cipher_value
        Base64.strict_encode64(asymmetric_cipher.encrypt(symmetric_cipher.key))
      end
    end
  end
end

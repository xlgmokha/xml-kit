# frozen_string_literal: true

module Xml
  module Kit
    class KeyInfo
      # An implementation of the RSAKeyValue element.
      # https://www.w3.org/TR/xmldsig-core1/#sec-RetrievalMethod
      #
      # @since 0.3.0
      class RetrievalMethod
        attr_accessor :uri, :type

        def initialize
          @type = "#{Namespaces::XMLENC}EncryptedKey"
        end
      end
    end
  end
end

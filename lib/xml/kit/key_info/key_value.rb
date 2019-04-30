# frozen_string_literal: true

module Xml
  module Kit
    class KeyInfo
      # An implementation of the RSAKeyValue element.
      # https://www.w3.org/TR/xmldsig-core1/#sec-KeyValue
      #
      # @since 0.3.0
      class KeyValue
        include Templatable

        def rsa
          @rsa ||= RSAKeyValue.new
        end
      end
    end
  end
end

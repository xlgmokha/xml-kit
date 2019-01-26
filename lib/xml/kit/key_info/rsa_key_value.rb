module Xml
  module Kit
    class KeyInfo
      # An implementation of the RSAKeyValue element.
      # https://www.w3.org/TR/xmldsig-core1/#sec-RSAKeyValue
      #
      # @since 0.3.0
      class RSAKeyValue
        attr_accessor :modulus, :exponent
      end
    end
  end
end

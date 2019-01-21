# frozen_string_literal: true

module Xml
  module Kit
    class KeyInfo
      attr_reader :algorithm, :cipher_value

      def initialize(algorithm:, cipher_value:)
        @algorithm = algorithm
        @cipher_value = cipher_value
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end
    end
  end
end

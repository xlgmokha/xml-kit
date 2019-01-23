# frozen_string_literal: true

module Xml
  module Kit
    class ExternalKeyInfo
      attr_reader :uri, :type

      def initialize(uri:, type: 'http://www.w3.org/2001/04/xmlenc#EncryptedKey')
        @uri = uri
        @type = type
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end
    end
  end
end

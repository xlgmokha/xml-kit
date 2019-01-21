require 'xml/kit/templatable'

module Xml
  module Kit
    class EncryptedKey
      include ::Xml::Kit::Templatable

      attr_reader :id

      def initialize(id:)
        @id = id
      end
    end
  end
end

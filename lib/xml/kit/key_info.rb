# frozen_string_literal: true

require 'xml/kit/key_info/key_value'
require 'xml/kit/key_info/retrieval_method'
require 'xml/kit/key_info/rsa_key_value'

module Xml
  module Kit
    # An implementation of the KeyInfo element.
    # https://www.w3.org/TR/xmldsig-core1/#sec-KeyInfo
    #
    # @since 0.3.0
    class KeyInfo
      include Templatable
      attr_accessor :key_name
      attr_accessor :x509_data
      attr_accessor :encrypted_key

      def initialize(x509: nil)
        @x509_data = x509
        yield self if block_given?
      end

      def key_value
        @key_value ||= KeyValue.new
      end

      def retrieval_method
        @retrieval_method ||= RetrievalMethod.new
      end

      def subject_key_identifier
        ski = x509_data.extensions.find { |x| x.oid == 'subjectKeyIdentifier' }
        return if ski.nil?

        Base64.strict_encode64(ski.value)
      end
    end
  end
end

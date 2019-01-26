# frozen_string_literal: true

module Xml
  module Kit
    class RSAKeyValue
      attr_accessor :modulus, :exponent
    end

    class KeyValue
      include Templatable

      def rsa
        @rsa ||= RSAKeyValue.new
      end
    end

    class RetrievalMethod
      attr_accessor :uri, :type

      def initialize
        @type = 'http://www.w3.org/2001/04/xmlenc#EncryptedKey'
      end
    end

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

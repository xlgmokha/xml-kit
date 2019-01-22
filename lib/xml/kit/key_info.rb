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
    end

    class KeyInfo
      include Templatable
      attr_reader :algorithm, :cipher_value
      attr_accessor :key_name
      attr_accessor :x509_data

      def initialize(algorithm:, cipher_value:)
        @algorithm = algorithm
        @cipher_value = cipher_value
      end

      def key_value
        @key_value ||= KeyValue.new
      end

      def retrieval_method
        @retrieval_method ||= RetrievalMethod.new
      end

      def subject_key_identifier
        ski = x509_data.extensions.find { |x| x.oid == "subjectKeyIdentifier" }&.value
        return if ski.nil?

        Base64.strict_encode64(ski)
      end
    end
  end
end

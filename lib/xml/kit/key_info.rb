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
    end
  end
end

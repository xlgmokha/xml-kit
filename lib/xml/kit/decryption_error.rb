# frozen_string_literal: true

module Xml
  module Kit
    class DecryptionError < StandardError
      attr_reader :private_keys

      def initialize(private_keys)
        @private_keys = private_keys
        super('Cannot decrypt document with the provided private keys')
      end
    end
  end
end

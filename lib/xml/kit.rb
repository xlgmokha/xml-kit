# frozen_string_literal: true

require 'active_model'
require 'active_support/core_ext/numeric/time'
require 'active_support/deprecation'
require 'base64'
require 'builder'
require 'logger'
require 'nokogiri'
require 'openssl'
require 'pathname'
require 'tilt'
require 'xmldsig'

require 'xml/kit/namespaces'

require 'xml/kit/certificate'
require 'xml/kit/crypto'
require 'xml/kit/decryption'
require 'xml/kit/decryption_error'
require 'xml/kit/document'
require 'xml/kit/encrypted_key'
require 'xml/kit/encryption'
require 'xml/kit/external_key_info'
require 'xml/kit/fingerprint'
require 'xml/kit/id'
require 'xml/kit/key_info'
require 'xml/kit/key_pair'
require 'xml/kit/self_signed_certificate'
require 'xml/kit/signature'
require 'xml/kit/signatures'
require 'xml/kit/templatable'
require 'xml/kit/template'
require 'xml/kit/version'

module Xml
  module Kit
    class << self
      def logger
        @logger ||= Logger.new(STDOUT)
      end

      attr_writer :logger

      def deprecate(message)
        @deprecation ||= ActiveSupport::Deprecation.new('1.0.0', 'xml-kit')
        @deprecation.deprecation_warning(message)
      end
    end
  end
end

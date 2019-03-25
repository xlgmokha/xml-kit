# frozen_string_literal: true

module Xml
  module Kit
    # An implementation of the Signature element.
    # https://www.w3.org/TR/xmldsig-core1/#sec-Signature
    #
    # @since 0.1.0
    class Signature
      SIGNATURE_METHODS = {
        SHA1: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        SHA224: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
        SHA256: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        SHA384: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        SHA512: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
      }.freeze
      DIGEST_METHODS = {
        SHA1: 'http://www.w3.org/2000/09/xmldsig#SHA1',
        SHA224: 'http://www.w3.org/2001/04/xmldsig-more#sha224',
        SHA256: 'http://www.w3.org/2001/04/xmlenc#sha256',
        SHA384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
        SHA512: 'http://www.w3.org/2001/04/xmlenc#sha512',
      }.freeze

      attr_reader :certificate
      attr_reader :digest_method
      attr_reader :reference_ids
      attr_reader :signature_method

      def initialize(
        reference_ids,
        signature_method: :SH256,
        digest_method: :SHA256,
        certificate:
      )
        @certificate = certificate
        @digest_method = DIGEST_METHODS[digest_method]
        @reference_ids = Array(reference_ids)
        @signature_method = SIGNATURE_METHODS[signature_method]
      end

      def enveloped?
        # As only one referenced passed, we assume it's enveloped (signature is child)
        # With more references only enveloping (signature is parent) makes sense
        # Better but more complicated: check if `reference_id` if a parent node
        reference_ids.size == 1
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        ::Xml::Kit::Template.new(self).to_xml(xml: xml)
      end
    end
  end
end

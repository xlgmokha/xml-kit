# frozen_string_literal: true

module Xml
  module Kit
    # {include:file:spec/saml/xml_spec.rb}
    class Document
      include ActiveModel::Validations
      NAMESPACES = { "ds": ::Xml::Kit::Namespaces::XMLDSIG }.freeze

      validate :validate_signatures
      validate :validate_certificates

      def initialize(raw_xml, namespaces: NAMESPACES)
        @raw_xml = raw_xml
        @namespaces = namespaces
        @document = ::Nokogiri::XML(raw_xml)
      end

      # Returns the first XML node found by searching the document with the provided XPath.
      #
      # @param xpath [String] the XPath to use to search the document
      def find_by(xpath)
        document.at_xpath(xpath, namespaces)
      end

      # Returns all XML nodes found by searching the document with the provided XPath.
      #
      # @param xpath [String] the XPath to use to search the document
      def find_all(xpath)
        document.search(xpath, namespaces)
      end

      # Return the XML document as a [String].
      #
      # @param pretty [Boolean] return the XML string in a human readable format if true.
      def to_xml(pretty: true)
        pretty ? document.to_xml(indent: 2) : raw_xml
      end

      private

      attr_reader :raw_xml, :document, :namespaces

      def validate_signatures
        invalid_signatures.flat_map(&:errors).uniq.each do |error|
          errors.add(error, 'is invalid')
        end
      end

      def invalid_signatures(id_attr: 'ID=$uri or @Id')
        Xmldsig::SignedDocument
          .new(document, id_attr: id_attr)
          .signatures.find_all do |signature|
          x509_certificates.all? do |certificate|
            !signature.valid?(certificate)
          end
        end
      end

      def validate_certificates(now = Time.current)
        return if find_by('//ds:Signature').nil?

        x509_certificates.each do |certificate|
          errors.add(:certificate, "Not valid before #{certificate.not_before}") if now < certificate.not_before

          errors.add(:certificate, "Not valid after #{certificate.not_after}") if now > certificate.not_after
        end
      end

      def x509_certificates
        find_all('//ds:KeyInfo/ds:X509Data/ds:X509Certificate').map do |item|
          Certificate.to_x509(item.text)
        end
      end
    end
  end
end

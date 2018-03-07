# frozen_string_literal: true

module Xml
  module Kit
    class KeyPair # :nodoc:
      attr_reader :certificate
      attr_reader :private_key
      attr_reader :public_key

      def initialize(certificate, private_key, passphrase, use)
        @certificate = ::Xml::Kit::Certificate.new(certificate, use: use)
        if passphrase.present?
          @private_key = OpenSSL::PKey::RSA.new(private_key, passphrase)
        else
          @private_key = OpenSSL::PKey::RSA.new(private_key)
        end
        @public_key = @private_key.public_key
      end

      # Returns true if the key pair is the designated use.
      #
      # @param use [Symbol] Can be either `:signing` or `:encryption`.
      def for?(use)
        certificate.for?(use)
      end

      # Returns a generated self signed certificate with private key.
      #
      # @param use [Symbol] Can be either `:signing` or `:encryption`.
      # @param passphrase [String] the passphrase to use to encrypt the private key.
      # @param algorithm [String] the symmetric algorithm to use for encrypting the private key.
      def self.generate(use:, passphrase: SecureRandom.uuid, algorithm: ::Xml::Kit::Crypto::SymmetricCipher::DEFAULT_ALGORITHM)
        algorithm = ::Xml::Kit::Crypto::SymmetricCipher::ALGORITHMS[algorithm]
        certificate, private_key = ::Xml::Kit::SelfSignedCertificate.new.create(algorithm: algorithm, passphrase: passphrase)
        new(certificate, private_key, passphrase, use)
      end
    end
  end
end

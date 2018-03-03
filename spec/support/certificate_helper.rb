# frozen_string_literal: true

module CertificateHelper
  def generate_key_pair(passphrase)
    ::Xml::Kit::SelfSignedCertificate.new.create(passphrase: passphrase)
  end
end

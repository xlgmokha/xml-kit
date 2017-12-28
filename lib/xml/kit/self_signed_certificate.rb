module Xml
  module Kit
    class SelfSignedCertificate
      SUBJECT="/C=CA/ST=Alberta/L=Calgary/O=XmlKit/OU=XmlKit/CN=XmlKit"

      def initialize(passphrase)
        @passphrase = passphrase
      end

      def create
        rsa_key = OpenSSL::PKey::RSA.new(2048)
        public_key = rsa_key.public_key
        certificate = OpenSSL::X509::Certificate.new
        certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse(SUBJECT)
        certificate.not_before = Time.now.to_i
        certificate.not_after = (Date.today + 30).to_time.to_i
        certificate.public_key = public_key
        certificate.serial = 0x0
        certificate.version = 2
        certificate.sign(rsa_key, OpenSSL::Digest::SHA256.new)
        [
          certificate.to_pem,
          rsa_key.to_pem(OpenSSL::Cipher.new('AES-256-CBC'), @passphrase)
        ]
      end
    end
  end
end

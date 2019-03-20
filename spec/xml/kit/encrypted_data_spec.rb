# frozen_string_literal: true

RSpec.describe Xml::Kit::EncryptedData do
  describe '#to_xml' do
    [
      ::Xml::Kit::Crypto::RsaCipher::ALGORITHM,
      ::Xml::Kit::Crypto::OaepCipher::ALGORITHM,
    ].each do |asymmetric_algorithm|
      subject do
        described_class.new(xml, asymmetric_cipher: asymmetric_cipher)
      end

      let(:symmetric_cipher) { ::Xml::Kit::Crypto::SymmetricCipher.new(symmetric_algorithm) }
      let(:symmetric_algorithm) { Xml::Kit::Crypto::SymmetricCipher::DEFAULT_ALGORITHM }
      let(:asymmetric_cipher) { ::Xml::Kit::Crypto.cipher_for(asymmetric_algorithm, key_pair.public_key) }
      let(:key_pair) { Xml::Kit::KeyPair.generate(use: :encryption, algorithm: symmetric_algorithm) }
      let(:decryptor) { Xml::Kit::Decryption.new(private_keys: [key_pair.private_key]) }
      let(:xml) do
        xml = ::Builder::XmlMarkup.new
        xml.HellWorld do
          xml.Now Time.now.iso8601
        end
        xml.target!
      end

      specify { expect(decryptor.decrypt_xml(subject.to_xml)).to eql(xml) }

      [
        "#{::Xml::Kit::Namespaces::XMLENC}tripledes-cbc",
        "#{::Xml::Kit::Namespaces::XMLENC}aes128-cbc",
        "#{::Xml::Kit::Namespaces::XMLENC}aes192-cbc",
        "#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc",
      ].each do |symmetric_algorithm|
        context symmetric_algorithm do
          subject do
            described_class.new(xml, symmetric_cipher: symmetric_cipher, asymmetric_cipher: asymmetric_cipher)
          end

          specify { expect(decryptor.decrypt_xml(subject.to_xml)).to eql(xml) }
        end
      end
    end
  end
end

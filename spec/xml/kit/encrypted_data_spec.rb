# frozen_string_literal: true

RSpec.describe Xml::Kit::EncryptedData do
  describe '#to_xml' do
    [
      ::Xml::Kit::Crypto::RsaCipher::ALGORITHM,
      ::Xml::Kit::Crypto::OaepCipher::ALGORITHM,
    ].each do |asymmetric_algorithm|
      [
        "#{::Xml::Kit::Namespaces::XMLENC}tripledes-cbc",
        "#{::Xml::Kit::Namespaces::XMLENC}aes128-cbc",
        "#{::Xml::Kit::Namespaces::XMLENC}aes192-cbc",
        "#{::Xml::Kit::Namespaces::XMLENC}aes256-cbc",
      ].each do |symmetric_algorithm|
        describe symmetric_algorithm do
          subject do
            described_class.new(xml, id: id, symmetric_cipher: symmetric_cipher, asymmetric_cipher: asymmetric_cipher)
          end

          let(:id) { ::Xml::Kit::Id.generate }
          let(:symmetric_cipher) { ::Xml::Kit::Crypto::SymmetricCipher.new(symmetric_algorithm) }
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
        end
      end
    end
  end
end

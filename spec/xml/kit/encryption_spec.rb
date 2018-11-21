# frozen_string_literal: true

RSpec.describe Xml::Kit::Encryption do
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
            described_class.new(xml, public_key, symmetric_algorithm: symmetric_algorithm, asymmetric_algorithm: asymmetric_algorithm)
          end

          let(:key_pair) { Xml::Kit::KeyPair.generate(use: :encryption, algorithm: symmetric_algorithm) }
          let(:decryptor) { Xml::Kit::Decryption.new(private_keys: [key_pair.private_key]) }
          let(:public_key) { key_pair.public_key }
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

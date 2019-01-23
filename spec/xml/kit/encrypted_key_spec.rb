# frozen_string_literal: true

RSpec.describe ::Xml::Kit::EncryptedKey do
  describe '#to_xml' do
    subject { described_class.new(id: id, algorithm: algorithm, public_key: public_key, key: symmetric_key, key_info: key_info) }

    let(:algorithm) { ::Xml::Kit::Crypto::RsaCipher::ALGORITHM }
    let(:key_info) { ::Xml::Kit::KeyInfo.new }
    let(:id) { ::Xml::Kit::Id.generate }
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:public_key) { private_key.public_key }
    let(:symmetric_key) { SecureRandom.hex(32) }
    let(:result) { Hash.from_xml(subject.to_xml) }

    before do
      key_info.key_name = 'samlkey'
    end

    specify { expect(result.key?('EncryptedKey')).to be_present }
    specify { expect(result['EncryptedKey']['Id']).to eql(id) }
    specify { expect(result['EncryptedKey']['xmlns']).to eql(::Xml::Kit::Namespaces::XMLENC) }
    specify { expect(result['EncryptedKey']['EncryptionMethod']['Algorithm']).to be_present }
    specify { expect(result['EncryptedKey']['CipherData']['CipherValue']).to be_present }
    specify { expect(private_key.private_decrypt(Base64.decode64(result['EncryptedKey']['CipherData']['CipherValue']))).to eql(symmetric_key) }
    specify { expect(subject.to_xml).to match_xsd('xenc-schema') }
    specify { expect(result['EncryptedKey'].key?('KeyInfo')).to be(true) }
  end
end

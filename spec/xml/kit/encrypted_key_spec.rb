# frozen_string_literal: true

RSpec.describe ::Xml::Kit::EncryptedKey do
  describe '#to_xml' do
    subject { described_class.new(id: id, asymmetric_cipher: asymmetric_cipher, key_info: key_info) }

    let(:asymmetric_cipher) { ::Xml::Kit::Crypto.cipher_for(algorithm, private_key.public_key) }
    let(:algorithm) { ::Xml::Kit::Crypto::RsaCipher::ALGORITHM }
    let(:key_info) { ::Xml::Kit::KeyInfo.new }
    let(:id) { ::Xml::Kit::Id.generate }
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:result) { Hash.from_xml(subject.to_xml) }

    before do
      key_info.key_name = 'samlkey'
    end

    specify { expect(result.key?('EncryptedKey')).to be_present }
    specify { expect(result['EncryptedKey']['Id']).to eql(id) }
    specify { expect(result['EncryptedKey']['xmlns']).to eql(::Xml::Kit::Namespaces::XMLENC) }
    specify { expect(result['EncryptedKey']['EncryptionMethod']['Algorithm']).to eql(algorithm) }
    specify { expect(result['EncryptedKey']['CipherData']['CipherValue']).to be_present }
    specify { expect(private_key.private_decrypt(Base64.decode64(result['EncryptedKey']['CipherData']['CipherValue']))).to eql(subject.symmetric_cipher.key) }
    specify { expect(subject.to_xml).to match_xsd('xenc-schema') }
    specify { expect(result['EncryptedKey'].key?('KeyInfo')).to be(true) }

    context 'with custom symmetric cipher' do
      subject { described_class.new(id: id, asymmetric_cipher: asymmetric_cipher, key_info: key_info, symmetric_cipher: symmetric_cipher) }

      let(:symmetric_cipher) { instance_double(Xml::Kit::Crypto::SymmetricCipher, key: 'symmetric_key', encrypt: 'CIPHERTEXT', algorithm: 'symmetric_cipher') }

      specify { expect(private_key.private_decrypt(Base64.decode64(result['EncryptedKey']['CipherData']['CipherValue']))).to eql(symmetric_cipher.key) }
    end
  end
end

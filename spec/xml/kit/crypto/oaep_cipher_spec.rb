# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::OaepCipher do
  subject { described_class.new('', private_key) }

  let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :encryption) }
  let(:private_key) { key_pair.private_key }
  let(:uuid) { SecureRandom.uuid }

  describe '#encrypt' do
    specify { expect(subject.decrypt(subject.encrypt(uuid))).to eql(uuid) }
  end

  describe '#decrypt' do
    let(:cipher_text) { private_key.public_encrypt(uuid, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING) }

    specify { expect(subject.decrypt(cipher_text)).to eql(uuid) }
  end
end

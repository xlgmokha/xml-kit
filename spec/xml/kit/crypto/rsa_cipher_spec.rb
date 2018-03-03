# frozen_string_literal: true

RSpec.describe ::Xml::Kit::Crypto::RsaCipher do
  let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :encryption) }
  let(:private_key) { key_pair.private_key }

  describe '#encrypt' do
    subject { described_class.new('', private_key) }

    let(:uuid) { SecureRandom.uuid }

    it 'encrypts the plain text' do
      expect(subject.decrypt(subject.encrypt(uuid))).to eql(uuid)
    end
  end

  describe '#decrypt' do
    subject { described_class.new('', private_key) }

    let(:uuid) { SecureRandom.uuid }

    it 'decrypts the cipher text' do
      cipher_text = private_key.public_encrypt(uuid)
      expect(subject.decrypt(cipher_text)).to eql(uuid)
    end
  end
end

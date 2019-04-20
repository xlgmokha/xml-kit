# frozen_string_literal: true

RSpec.describe Xml::Kit::KeyPair do
  let(:certificate) do
    certificate = OpenSSL::X509::Certificate.new
    certificate.public_key = key.public_key
    certificate.not_before = 1.day.ago
    certificate.not_after = 1.second.ago
    certificate
  end
  let(:key) { OpenSSL::PKey::RSA.new(2048) }
  let(:passphrase) { 'secret' }

  context 'when the passphrase is empty' do
    subject { described_class.new(certificate.to_pem, key.export, '', :signing) }

    specify { expect { subject }.not_to raise_error }
    specify { expect(subject.for?(:signing)).to be(true) }
    specify { expect(subject.for?(:encryption)).to be(false) }
  end

  it 'decrypts encrypted private keys' do
    encrypted_key = key.export(OpenSSL::Cipher.new('AES-256-CBC'), passphrase)
    expect do
      described_class.new(certificate.to_pem, encrypted_key, passphrase, :signing)
    end.not_to raise_error
  end
end

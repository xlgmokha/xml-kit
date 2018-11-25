# frozen_string_literal: true

RSpec.describe Xml::Kit::Document do
  describe '#valid_signature?' do
    let(:signed_xml) { Item.new.to_xml }

    context 'when the signature is valid' do
      subject { described_class.new(signed_xml) }

      specify { expect(subject).to be_valid }
    end

    context 'when the SHA1 digest is not valid' do
      subject { described_class.new(signed_xml.gsub('Item', 'uhoh')) }

      before { subject.valid? }

      specify { expect(subject).not_to be_valid }
      specify { expect(subject.errors[:digest_value]).to be_present }
    end

    context 'when the digest is incorrect' do
      subject { described_class.new(signed_xml.gsub(old_digest, 'sabotage')) }

      let(:old_digest) { Hash.from_xml(signed_xml)['Item']['Signature']['SignedInfo']['Reference']['DigestValue'] }

      before { subject.valid? }

      specify { expect(subject).not_to be_valid }
      specify { expect(subject.errors[:digest_value]).to be_present }
    end

    context 'when the signature is invalid' do
      subject { described_class.new(signed_xml.gsub(old_signature, 'sabotage')) }

      let(:old_signature) { Hash.from_xml(signed_xml)['Item']['Signature']['SignatureValue'] }

      before { subject.valid? }

      specify { expect(subject).not_to be_valid }
      specify { expect(subject.errors[:signature]).to be_present }
    end

    context 'when the certificate is expired' do
      let(:expired_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.public_key = private_key.public_key
        certificate.not_before = 1.day.ago
        certificate.not_after = 1.second.ago
        certificate
      end
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:digest_algorithm) { OpenSSL::Digest::SHA256.new }
      let(:item) { Item.new }

      before do
        expired_certificate.sign(private_key, digest_algorithm)
      end

      specify do
        certificate = ::Xml::Kit::Certificate.new(expired_certificate)
        item.sign_with(certificate.to_key_pair(private_key))
        subject = described_class.new(item.to_xml)
        expect(subject).to be_invalid
        expect(subject.errors[:certificate]).to be_present
      end
    end
  end
end

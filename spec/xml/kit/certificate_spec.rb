# frozen_string_literal: true

RSpec.describe Xml::Kit::Certificate do
  subject { described_class.new(certificate, use: :signing) }

  let(:certificate) { generate_key_pair('password')[0] }

  describe '#fingerprint' do
    specify { expect(subject.fingerprint).to be_instance_of(Xml::Kit::Fingerprint) }
  end

  describe '#for?' do
    context 'when it is for signing' do
      subject { described_class.new(certificate, use: :signing) }

      specify { expect(subject).to be_for(:signing) }
      specify { expect(subject).to be_signing }
      specify { expect(subject).not_to be_for(:encryption) }
      specify { expect(subject).not_to be_encryption }
    end

    context 'when it is for encryption' do
      subject { described_class.new(certificate, use: :encryption) }

      specify { expect(subject).to be_for(:encryption) }
      specify { expect(subject).not_to be_for(:signing) }
      specify { expect(subject).to be_encryption }
      specify { expect(subject).not_to be_signing }
    end

    context 'when it is for both signing and encryption' do
      subject { described_class.new(certificate) }

      specify { expect(subject).to be_for(:encryption) }
      specify { expect(subject).to be_for(:signing) }
      specify { expect(subject).to be_encryption }
      specify { expect(subject).to be_signing }
    end
  end

  describe 'equality' do
    specify { expect(subject).to eql(subject) }
    specify { expect(described_class.new(certificate, use: :signing)).to eql(described_class.new(certificate, use: :signing)) }
  end

  describe '#to_h' do
    specify { expect(subject.to_h).to eql(use: :signing, fingerprint: subject.fingerprint.to_s) }
  end

  describe '#stripped' do
    let(:expected) { certificate.to_s.gsub(/-----BEGIN CERTIFICATE-----/, '').gsub(/-----END CERTIFICATE-----/, '').delete("\n") }

    specify { expect(subject.stripped).to eql(expected) }
  end

  describe '#x509' do
    let(:expected) { OpenSSL::X509::Certificate.new(certificate.to_s) }
    let(:actual) { subject.x509 }

    specify { expect(actual).to be_instance_of(OpenSSL::X509::Certificate) }
    specify { expect(actual.to_s).to eql(expected.to_s) }
  end

  describe '#expired?' do
    let(:certificate) { OpenSSL::X509::Certificate.new }

    context 'when the certificate has not expired yet' do
      subject { described_class.new(certificate, use: :signing) }

      before do
        certificate.not_before = 1.minute.ago
        certificate.not_after = 10.minutes.from_now
      end

      specify { expect(subject).not_to be_expired(Time.now) }
    end

    context 'when the current time is after the time of the expiration' do
      subject { described_class.new(certificate, use: :signing) }

      before do
        certificate.not_before = 10.minutes.ago
        certificate.not_after = 1.minute.ago
      end

      specify { expect(subject).to be_expired(Time.now) }
    end
  end

  describe '#active?' do
    subject { described_class.new(certificate, use: :signing) }

    let(:certificate) { OpenSSL::X509::Certificate.new }
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    context 'when the current time is within the active window' do
      before do
        certificate.not_before = 1.minute.ago
        certificate.not_after = 10.minutes.from_now
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
      end

      specify { expect(subject).to be_active(Time.now) }

      context 'when reading an x509 pem' do
        subject { described_class.new(certificate.to_pem, use: :signing) }

        specify { expect(subject).to be_active(Time.now) }
      end
    end

    context 'when the current time is before the active window' do
      before do
        certificate.not_before = 1.minute.from_now
        certificate.not_after = 10.minutes.from_now
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
      end

      specify { expect(subject).not_to be_active(Time.now) }

      context 'when reading an x509 pem' do
        subject { described_class.new(certificate.to_pem, use: :signing) }

        specify { expect(subject).not_to be_active(Time.now) }
      end
    end

    context 'when the current time is after the active window' do
      before do
        certificate.not_before = 10.minutes.ago
        certificate.not_after = 1.minute.ago
        certificate.public_key = private_key.public_key
        certificate.sign(private_key, OpenSSL::Digest::SHA256.new)
      end

      specify { expect(subject).not_to be_active(Time.now) }

      context 'when reading an x509 pem' do
        subject { described_class.new(certificate.to_pem, use: :signing) }

        specify { expect(subject).not_to be_active(Time.now) }
      end
    end
  end

  describe '#not_after, #not_before' do
    subject { described_class.new(certificate, use: :signing) }

    let(:certificate) { OpenSSL::X509::Certificate.new }

    before do
      certificate.not_before = 1.minute.from_now
      certificate.not_after = 10.minutes.from_now
    end

    specify { expect(subject.not_after).to eql(certificate.not_after) }
    specify { expect(subject.not_before).to eql(certificate.not_before) }
  end

  describe '#to_xml' do
    context 'when generated' do
      let(:result) { Hash.from_xml(subject.to_xml) }

      specify { expect(result['KeyDescriptor']).to be_present }
      specify { expect(result['KeyDescriptor']['use']).to eql('signing') }
      specify { expect(result['KeyDescriptor']['KeyInfo']['xmlns']).to eql(Xml::Kit::Namespaces::XMLDSIG) }
      specify { expect(result['KeyDescriptor']['KeyInfo']['X509Data']['X509Certificate']).to eql(subject.stripped) }
    end

    context 'when the certificate can be used for both signing and encryption' do
      subject { described_class.new(certificate, use: nil) }

      let(:result) { Hash.from_xml(subject.to_xml) }

      specify { expect(result['KeyDescriptor']).to be_present }
      specify { expect(result['KeyDescriptor']['use']).to be_nil }
    end
  end
end

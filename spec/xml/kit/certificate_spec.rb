RSpec.describe Xml::Kit::Certificate do
  subject { described_class.new(certificate, use: :signing) }

  let(:certificate) { generate_key_pair('password')[0] }

  describe '#fingerprint' do
    it 'returns a fingerprint' do
      expect(subject.fingerprint).to be_instance_of(Xml::Kit::Fingerprint)
    end
  end

  describe '#for?' do
    it 'returns true, when it is for signing' do
      subject = described_class.new(certificate, use: :signing)
      expect(subject).to be_for(:signing)
      expect(subject).to be_signing
      expect(subject).not_to be_for(:encryption)
      expect(subject).not_to be_encryption
    end

    it 'returns true, when it is for encryption' do
      subject = described_class.new(certificate, use: :encryption)
      expect(subject).to be_for(:encryption)
      expect(subject).not_to be_for(:signing)

      expect(subject).to be_encryption
      expect(subject).not_to be_signing
    end

    it 'returns true when it is for both' do
      subject = described_class.new(certificate)
      expect(subject).to be_for(:encryption)
      expect(subject).to be_for(:signing)

      expect(subject).to be_encryption
      expect(subject).to be_signing
    end
  end

  describe 'equality' do
    it 'is equal by reference equality' do
      expect(subject).to eql(subject)
    end

    it 'is equal by value equality' do
      expect(
        described_class.new(certificate, use: :signing)
      ).to eql(
        described_class.new(certificate, use: :signing)
      )
    end
  end

  describe '#to_h' do
    it 'returns a hash' do
      expect(subject.to_h).to eql(
        use: :signing,
        fingerprint: subject.fingerprint.to_s
      )
    end
  end

  describe '#stripped' do
    it 'removes the BEGIN and END lines' do
      expected = certificate.to_s.gsub(/-----BEGIN CERTIFICATE-----/, '').gsub(/-----END CERTIFICATE-----/, '').delete("\n")
      expect(subject.stripped).to eql(expected)
    end
  end

  describe '#x509' do
    it 'returns an x509 certificate' do
      expected = OpenSSL::X509::Certificate.new(certificate.to_s)
      actual = subject.x509
      expect(actual).to be_instance_of(OpenSSL::X509::Certificate)
      expect(actual.to_s).to eql(expected.to_s)
    end
  end

  describe '#expired?' do
    let(:certificate) { OpenSSL::X509::Certificate.new }

    it 'returns false, when the certificate has not expired yet' do
      certificate.not_before = 1.minute.ago
      certificate.not_after = 10.minutes.from_now

      subject = described_class.new(certificate, use: :signing)
      expect(subject).not_to be_expired(Time.now)
    end

    it 'returns true, when the current time is after the time of expiration' do
      certificate.not_before = 10.minutes.ago
      certificate.not_after = 1.minute.ago

      subject = described_class.new(certificate, use: :signing)
      expect(subject).to be_expired(Time.now)
    end
  end

  describe '#active?' do
    subject { described_class.new(certificate, use: :signing) }

    let(:certificate) { OpenSSL::X509::Certificate.new }

    context 'when the current time is within the active window' do
      before do
        certificate.not_before = 1.minute.ago
        certificate.not_after = 10.minutes.from_now
      end

      it 'is active' do
        expect(subject).to be_active(Time.now)
      end
    end

    context 'when the current time is before the active window' do
      before do
        certificate.not_before = 1.minute.from_now
        certificate.not_after = 10.minutes.from_now
      end

      it 'is not active' do
        expect(subject).not_to be_active(Time.now)
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

    it 'delegates not_after to the x509 certificate' do
      expect(subject.not_after).to eql(certificate.not_after)
    end

    it 'delegates not_before to the x509 certificate' do
      expect(subject.not_before).to eql(certificate.not_before)
    end
  end

  describe '#to_xml' do
    it 'generates the correct xml' do
      result = Hash.from_xml(subject.to_xml)
      expect(result['KeyDescriptor']).to be_present
      expect(result['KeyDescriptor']['use']).to eql('signing')
      expect(result['KeyDescriptor']['KeyInfo']['xmlns']).to eql(Xml::Kit::Namespaces::XMLDSIG)
      expect(result['KeyDescriptor']['KeyInfo']['X509Data']['X509Certificate']).to eql(subject.stripped)
    end

    it 'omits the `use` when the cert can be used for both signing and encryption' do
      subject = described_class.new(certificate, use: nil)
      result = Hash.from_xml(subject.to_xml)
      expect(result['KeyDescriptor']).to be_present
      expect(result['KeyDescriptor']['use']).to be_nil
    end
  end
end

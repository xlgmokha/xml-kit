RSpec.describe Xml::Kit::Certificate do
  subject { described_class.new(certificate, use: :signing) }
  let(:certificate) { generate_key_pair('password')[0] }

  describe "#fingerprint" do
    it 'returns a fingerprint' do
      expect(subject.fingerprint).to be_instance_of(Xml::Kit::Fingerprint)
    end
  end

  describe "#for?" do
    it 'returns true, when it is for signing' do
      subject = described_class.new(certificate, use: :signing)
      expect(subject.for?(:signing)).to be_truthy
      expect(subject).to be_signing
      expect(subject.for?(:encryption)).to be_falsey
      expect(subject).to_not be_encryption
    end

    it 'returns true, when it is for encryption' do
      subject = described_class.new(certificate, use: :encryption)
      expect(subject.for?(:encryption)).to be_truthy
      expect(subject.for?(:signing)).to be_falsey

      expect(subject).to be_encryption
      expect(subject).to_not be_signing
    end
  end

  describe "equality" do
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

  describe "#to_h" do
    it 'returns a hash' do
      expect(subject.to_h).to eql({
        use: :signing,
        fingerprint: subject.fingerprint.to_s,
      })
    end
  end

  describe "#stripped" do
    it 'removes the BEGIN and END lines' do
      expected = certificate.to_s.gsub(/-----BEGIN CERTIFICATE-----/, '').gsub(/-----END CERTIFICATE-----/, '').gsub(/\n/, '')
      expect(subject.stripped).to eql(expected)
    end
  end

  describe "#x509" do
    it 'returns an x509 certificate' do
      expected = OpenSSL::X509::Certificate.new(certificate.to_s)
      actual = subject.x509
      expect(actual).to be_instance_of(OpenSSL::X509::Certificate)
      expect(actual.to_s).to eql(expected.to_s)
    end
  end
end

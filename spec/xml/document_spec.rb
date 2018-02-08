RSpec.describe Xml::Kit::Document do
  class Item
    include ::Xml::Kit::Templatable

    attr_reader :id, :signing_key_pair

    def initialize
      @id = ::Xml::Kit::Id.generate
      @signing_key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
      @embed_signature = true
      @encrypt = true
      @encryption_certificate = ::Xml::Kit::KeyPair.generate(use: :encryption).certificate
    end

    def template_path
      current_path = File.expand_path(File.dirname(__FILE__))
      File.join(current_path, "../fixtures/item.builder")
    end
  end

  describe "#valid_signature?" do
    let(:login_url) { "https://#{FFaker::Internet.domain_name}/login" }
    let(:logout_url) { "https://#{FFaker::Internet.domain_name}/logout" }
    let(:signed_xml) { Item.new.to_xml }

    it 'returns true, when the digest and signature is valid' do
      expect(described_class.new(signed_xml)).to be_valid
    end

    it 'returns false, when the SHA1 digest is not valid' do
      subject = described_class.new(signed_xml.gsub("Item", "uhoh"))
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'it is invalid when digest is incorrect' do
      old_digest = Hash.from_xml(signed_xml)['Item']['Signature']['SignedInfo']['Reference']['DigestValue']

      subject = described_class.new(signed_xml.gsub(old_digest, 'sabotage'))
      expect(subject).to_not be_valid
      expect(subject.errors[:digest_value]).to be_present
    end

    it 'returns false, when the signature is invalid' do
      old_signature = Hash.from_xml(signed_xml)['Item']['Signature']['SignatureValue']
      signed_xml.gsub!(old_signature, 'sabotage')
      subject = described_class.new(signed_xml)
      expect(subject).to_not be_valid
      expect(subject.errors[:signature]).to be_present
    end

    context "when the certificate is expired" do
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

      before :each do
        expired_certificate.sign(private_key, digest_algorithm)
      end

      it 'is invalid' do
        certificate = ::Xml::Kit::Certificate.new(expired_certificate)
        item.sign_with(certificate.to_key_pair(private_key))
        subject = described_class.new(item.to_xml)
        expect(subject).to be_invalid
        expect(subject.errors[:certificate]).to be_present
      end
    end
  end
end

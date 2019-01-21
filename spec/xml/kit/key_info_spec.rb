RSpec.describe Xml::Kit::KeyInfo do
  describe "#to_xml" do
    subject { described_class.new(algorithm: algorithm, cipher_value: cipher_value) }
    let(:algorithm) { 'asymmetric_cipher' }
    let(:cipher_value) { Base64.strict_encode64('asymmetric CIPHERTEXT') }
    let(:result) { Hash.from_xml(subject.to_xml) }

    specify { expect(result['KeyInfo']).to be_present }
    specify { expect(result['KeyInfo']['EncryptedKey']['EncryptionMethod']['Algorithm']).to eql(algorithm) }
    specify { expect(result['KeyInfo']['EncryptedKey']['CipherData']['CipherValue']).to eql(cipher_value) }
  end
end

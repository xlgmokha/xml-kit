# frozen_string_literal: true

RSpec.describe Soap do
  describe '#to_xml' do
    subject { described_class.new }

    let(:result) { Hash.from_xml(subject.to_xml) }

    specify { expect(result['Envelope']).to be_present }
    specify { expect(result['Envelope']['Header']).to be_present }
    specify do
      cipher_value = result['Envelope']['Header']['Security']['EncryptedKey']['CipherData']['CipherValue']
      symmetric_key = subject.encryption_key_pair.private_key.private_decrypt(Base64.decode64(cipher_value))
      expect(symmetric_key).to eql(subject.symmetric_key)

      algorithm = result['Envelope']['Body']['EncryptedData']['EncryptionMethod']['Algorithm']
      cipher_value = result['Envelope']['Body']['EncryptedData']['CipherData']['CipherValue']
      result = ::Xml::Kit::Crypto::SymmetricCipher.new(algorithm, symmetric_key).decrypt(Base64.decode64(cipher_value))
      hash = Hash.from_xml(result)
      expect(hash['EncryptMe']['Secret']).to eql('secret')
    end

    specify { expect(result['Envelope']['Body']).to be_present }
  end
end

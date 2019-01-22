RSpec.describe Xml::Kit::KeyInfo do
  subject { described_class.new(algorithm: algorithm, cipher_value: cipher_value) }
  let(:algorithm) { 'asymmetric_cipher' }
  let(:cipher_value) { Base64.strict_encode64('asymmetric CIPHERTEXT') }

  describe "#to_xml" do
    context "with encrypted key" do

      let(:result) { Hash.from_xml(subject.to_xml) }

      specify { expect(result['KeyInfo']).to be_present }
      specify { expect(result['KeyInfo']['EncryptedKey']['EncryptionMethod']['Algorithm']).to eql(algorithm) }
      specify { expect(result['KeyInfo']['EncryptedKey']['CipherData']['CipherValue']).to eql(cipher_value) }
    end

    context "with key name" do
      let(:result) { Hash.from_xml(subject.to_xml) }

      before do
        subject.key_name = "samlkey"
        puts subject.to_xml(pretty: true)
      end

      specify { expect(result['KeyInfo']['KeyName']).to eql('samlkey') }
    end

    context "with key value" do
      let(:result) { Hash.from_xml(subject.to_xml) }
      let(:modulus) { 'xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6WjubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=' }
      let(:exponent) { 'AQAB' }

      before do
        subject.key_value.rsa.modulus = modulus
        subject.key_value.rsa.exponent = exponent
      end

      specify { expect(result['KeyInfo']['KeyValue']['RSAKeyValue']['Modulus']).to eql(modulus) }
      specify { expect(result['KeyInfo']['KeyValue']['RSAKeyValue']['Exponent']).to eql(exponent) }
    end

    context "with retrieval method" do
      let(:result) { Hash.from_xml(subject.to_xml) }
      let(:uri) { Xml::Kit::Id.generate }
      let(:type) { "http://www.w3.org/2001/04/xmlenc#EncryptedKey" }

      before do
        subject.retrieval_method.uri = uri
        subject.retrieval_method.type = type
      end

      specify { expect(result['KeyInfo']['RetrievalMethod']['URI']).to eql(uri) }
      specify { expect(result['KeyInfo']['RetrievalMethod']['Type']).to eql(type) }
    end

    context "with x509 data" do
      let(:key_pair) { ::Xml::Kit::KeyPair.generate(use: :encryption) }
      let(:x509_certificate) { key_pair.certificate.x509 }
      let(:subject_key_identifier) { x509_certificate.extensions.find { |x| x.oid == "subjectKeyIdentifier" }.value  }
      let(:result) { Hash.from_xml(subject.to_xml) }

      before do
        subject.x509_data = x509_certificate
      end

      specify { expect(result['KeyInfo']['X509Data']['X509SKI']).to eql(Base64.strict_encode64(subject_key_identifier)) }
      specify { expect(result['KeyInfo']['X509Data']['X509Certificate']).to eql(key_pair.certificate.stripped) }
    end
  end
end

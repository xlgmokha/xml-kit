# frozen_string_literal: true

RSpec.describe Xml::Kit::Decryption do
  describe '#decrypt_hash' do
    let(:secret) { FFaker::Movie.title }
    let(:password) { FFaker::Movie.title }

    context 'when decrypting AES-128-CBC data' do
      subject { described_class.new(private_keys: [private_key]) }

      let(:key_pair) { generate_key_pair(password) }
      let(:certificate_pem) { key_pair[0] }
      let(:private_key_pem) { key_pair[1] }
      let(:public_key) { OpenSSL::X509::Certificate.new(certificate_pem).public_key }
      let(:private_key) { OpenSSL::PKey::RSA.new(private_key_pem, password) }
      let(:data) do
        cipher = OpenSSL::Cipher.new('AES-128-CBC')
        cipher.encrypt
        key = cipher.random_key
        iv = cipher.random_iv
        encrypted = cipher.update(secret) + cipher.final
        {
          'EncryptedData' => {
            'xmlns:xenc' => 'http://www.w3.org/2001/04/xmlenc#',
            'xmlns:dsig' => 'http://www.w3.org/2000/09/xmldsig#',
            'Type' => 'http://www.w3.org/2001/04/xmlenc#Element',
            'EncryptionMethod' => {
              'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            },
            'KeyInfo' => {
              'xmlns:dsig' => 'http://www.w3.org/2000/09/xmldsig#',
              'EncryptedKey' => {
                'EncryptionMethod' => {
                  'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
                },
                'CipherData' => {
                  'CipherValue' => Base64.encode64(public_key.public_encrypt(key))
                }
              }
            },
            'CipherData' => {
              'CipherValue' => Base64.encode64(iv + encrypted)
            }
          }
        }
      end

      specify { expect(subject.decrypt_hash(data).strip).to eql(secret) }
    end

    context 'when multiple encryption keys are present' do
      subject { described_class.new(private_keys: [other_private_key, private_key]) }

      let(:key_pair) { generate_key_pair(password) }
      let(:other_key_pair) { generate_key_pair(password) }
      let(:certificate_pem) { key_pair[0] }
      let(:private_key_pem) { key_pair[1] }
      let(:public_key) { OpenSSL::X509::Certificate.new(certificate_pem).public_key }
      let(:private_key) { OpenSSL::PKey::RSA.new(private_key_pem, password) }
      let(:other_private_key_pem) { other_key_pair[1] }
      let(:other_private_key) { OpenSSL::PKey::RSA.new(other_private_key_pem, password) }

      let(:data) do
        cipher = OpenSSL::Cipher.new('AES-128-CBC')
        cipher.encrypt
        key = cipher.random_key
        iv = cipher.random_iv
        encrypted = cipher.update(secret) + cipher.final

        {
          'EncryptedData' => {
            'xmlns:xenc' => 'http://www.w3.org/2001/04/xmlenc#',
            'xmlns:dsig' => 'http://www.w3.org/2000/09/xmldsig#',
            'Type' => 'http://www.w3.org/2001/04/xmlenc#Element',
            'EncryptionMethod' => {
              'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            },
            'KeyInfo' => {
              'xmlns:dsig' => 'http://www.w3.org/2000/09/xmldsig#',
              'EncryptedKey' => {
                'EncryptionMethod' => {
                  'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
                },
                'CipherData' => {
                  'CipherValue' => Base64.encode64(public_key.public_encrypt(key))
                }
              }
            },
            'CipherData' => {
              'CipherValue' => Base64.encode64(iv + encrypted)
            }
          }
        }
      end

      specify { expect(subject.decrypt_hash(data).strip).to eql(secret) }
    end

    context 'when it cannot decrypt the data' do
      subject { described_class.new(private_keys: [new_private_key]) }

      let(:key_pair) { generate_key_pair(password) }
      let(:certificate_pem) { key_pair[0] }
      let(:public_key) { OpenSSL::X509::Certificate.new(certificate_pem).public_key }
      let(:new_private_key_pem) { generate_key_pair(password)[1] }
      let(:new_private_key) { OpenSSL::PKey::RSA.new(new_private_key_pem, password) }
      let(:data) do
        cipher = OpenSSL::Cipher.new('AES-128-CBC')
        cipher.encrypt
        key = cipher.random_key
        iv = cipher.random_iv
        encrypted = cipher.update(secret) + cipher.final

        {
          'EncryptedData' => {
            'xmlns:xenc' => 'http://www.w3.org/2001/04/xmlenc#',
            'xmlns:dsig' => 'http://www.w3.org/2000/09/xmldsig#',
            'Type' => 'http://www.w3.org/2001/04/xmlenc#Element',
            'EncryptionMethod' => {
              'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            },
            'KeyInfo' => {
              'xmlns:dsig' => 'http://www.w3.org/2000/09/xmldsig#',
              'EncryptedKey' => {
                'EncryptionMethod' => {
                  'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
                },
                'CipherData' => {
                  'CipherValue' => Base64.encode64(public_key.public_encrypt(key))
                }
              }
            },
            'CipherData' => {
              'CipherValue' => Base64.encode64(iv + encrypted)
            }
          }
        }
      end

      specify { expect { subject.decrypt_hash(data) }.to raise_error(OpenSSL::PKey::RSAError) }
    end
  end

  describe '#decrypt_document' do
    subject { described_class.new(private_keys: [item.encryption_key_pair.private_key]) }

    let(:item) { Item.new }
    let(:document) { Nokogiri::XML(item.to_xml) }
    let(:encrypted_node) { document.at_xpath('/Item/Encrypted/xmlenc:EncryptedData', 'xmlenc' => 'http://www.w3.org/2001/04/xmlenc#') }

    specify { expect(subject.decrypt_node(encrypted_node).name).to eql('EncryptMe') }
    specify { expect(subject.decrypt_node(nil)).to be_nil }

    context 'when it does not contain an EncryptedData' do
      let(:document) { Nokogiri::XML('<hello><world></world></hello>') }
      let(:node) { document.at_xpath('//hello/world') }

      specify { expect(subject.decrypt_node(node)).to eql(node) }
    end

    context 'when the document cannot be decrypted' do
      subject { described_class.new(private_keys: []) }

      specify { expect { subject.decrypt_node(encrypted_node) }.to raise_error(Xml::Kit::DecryptionError) }
    end
  end
end

# frozen_string_literal: true

RSpec.describe Xml::Kit::Decryption do
  describe '#decrypt_hash' do
    let(:secret) { FFaker::Movie.title }
    let(:password) { FFaker::Movie.title }

    it 'decrypts AES-128-CBC data' do
      certificate_pem, private_key_pem = generate_key_pair(password)

      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
      private_key = OpenSSL::PKey::RSA.new(private_key_pem, password)

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      encrypted = cipher.update(secret) + cipher.final

      data = {
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
      subject = described_class.new(private_keys: [private_key])
      decrypted = subject.decrypt_hash(data)
      expect(decrypted.strip).to eql(secret)
    end

    it 'attempts to decrypt with each encryption keypair' do
      certificate_pem, private_key_pem = generate_key_pair(password)
      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
      private_key = OpenSSL::PKey::RSA.new(private_key_pem, password)

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      encrypted = cipher.update(secret) + cipher.final

      data = {
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

      _, other_private_key_pem = generate_key_pair(password)
      other_private_key = OpenSSL::PKey::RSA.new(other_private_key_pem, password)

      subject = described_class.new(private_keys: [other_private_key, private_key])
      decrypted = subject.decrypt_hash(data)
      expect(decrypted.strip).to eql(secret)
    end

    it 'raise an error when it cannot decrypt the data' do
      certificate_pem, = generate_key_pair(password)
      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      encrypted = cipher.update(secret) + cipher.final

      data = {
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

      new_private_key_pem = generate_key_pair(password)[1]
      new_private_key = OpenSSL::PKey::RSA.new(new_private_key_pem, password)
      subject = described_class.new(private_keys: [new_private_key])
      expect do
        subject.decrypt_hash(data)
      end.to raise_error(OpenSSL::PKey::RSAError)
    end
  end

  describe '#decrypt_document' do
    let(:item) { Item.new }
    let(:document) { Nokogiri::XML(item.to_xml) }
    let(:subject) { described_class.new(private_keys: [item.encryption_key_pair.private_key]) }
    let(:encrypted_node) { document.at_xpath('/Item/Encrypted/xmlenc:EncryptedData', 'xmlenc' => 'http://www.w3.org/2001/04/xmlenc#') }

    it 'decrypts a nokogiri document' do
      expect(subject.decrypt_node(encrypted_node).name).to eql('EncryptMe')
    end

    it 'returns the node when it does not contain an EncryptedData' do
      document = Nokogiri::XML('<hello><world></world></hello>')
      node = document.at_xpath('//hello/world')
      expect(subject.decrypt_node(node)).to eql(node)
    end

    it 'returns nil when the node is nil' do
      expect(subject.decrypt_node(nil)).to be_nil
    end

    it 'raises an error when the document cannot be decrypted' do
      subject = described_class.new(private_keys: [])

      expect do
        subject.decrypt_node(encrypted_node)
      end.to raise_error(Xml::Kit::DecryptionError)
    end
  end
end

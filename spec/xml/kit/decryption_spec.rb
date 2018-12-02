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

    context 'when using the ruby-saml example' do
      subject { described_class.new(cipher_registry: cipher_registry, private_keys: private_keys) }

      let(:private_keys) { [OpenSSL::PKey::RSA.new(private_key_pem)] }
      let(:private_key_pem) { IO.read('./spec/fixtures/private.txt') }
      let(:document) { Nokogiri::XML(raw_xml) }
      let(:encoded) { 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6UmVzcG9uc2UgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgSUQ9InBmeDUxOWI1Y2JiLWNiNmYtOTQzNS0xNjNmLWJkMzVjZTM1YzNmMCIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDYtMDRUMDI6MjI6MDJaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2FwcC5tdWRhLm5vL3Nzby9jb25zdW1lIiBJblJlc3BvbnNlVG89Il9mYzRhMzRiMC03ZWZiLTAxMmUtY2FhZS03ODJiY2IxM2JiMzgiPjxzYW1sOklzc3Vlcj5odHRwczovL2FwcC5vbmVsb2dpbi5jb20vc2FtbDI8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPg0KICA8ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPg0KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4NCiAgPGRzOlJlZmVyZW5jZSBVUkk9IiNwZng1MTliNWNiYi1jYjZmLTk0MzUtMTYzZi1iZDM1Y2UzNWMzZjAiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPjBTRFRrNXNYWjdoMW9YUWVRMm5YY3BLZnZoTT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+WENPVmk4U2c0MllRS25oMWpNTWYvV0dVcDh5Q1dFQWV4UE5taVNWT0M2dUFBUGc5WWwySUt4Um1SeGczcHpVK0o5SzlTRUVEOEJWenJERTZ4VDlxV1JUbXZ1WExqemE0TndvRmFGWllIc3ZzN0FPR3l5UEJjT3Z2R3JoM2RGWmVTUzF5U2tVc3FBWW5Wck54emRkRVFZa2trRmNxQkNqZ3dnd0Z5Vlpvbkc4PTwvZHM6U2lnbmF0dXJlVmFsdWU+DQo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDR3pDQ0FZUUNDUUNOTmNRWG9tMzJWREFOQmdrcWhraUc5dzBCQVFVRkFEQlNNUXN3Q1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFQ0JNQ1NVNHhGVEFUQmdOVkJBY1RERWx1WkdsaGJtRndiMnhwY3pFUk1BOEdBMVVFQ2hNSVQyNWxURzluYVc0eEREQUtCZ05WQkFzVEEwVnVaekFlRncweE5EQTBNak14T0RReE1ERmFGdzB4TlRBME1qTXhPRFF4TURGYU1GSXhDekFKQmdOVkJBWVRBbFZUTVFzd0NRWURWUVFJRXdKSlRqRVZNQk1HQTFVRUJ4TU1TVzVrYVdGdVlYQnZiR2x6TVJFd0R3WURWUVFLRXdoUGJtVk1iMmRwYmpFTU1Bb0dBMVVFQ3hNRFJXNW5NSUdmTUEwR0NTcUdTSWIzRFFFQkFRVUFBNEdOQURDQmlRS0JnUURvNm0rUVp2WVEveEwwRWxMZ3VwSzFRRGNZTDRmNVBja3dzTmdTOXBVdlY3ZnpUcUNIazhUaEx4VGs0Mk1RMk1jSnNPZVVKVlA3MjhLaHltakZDcXhnUDRWdXdSazlycEFsMCttaHk2TVBkeWp5QTZHMTRqckRXUzY1eXNMY2hLNHQvdndwRUR6MFNRbEVvRzFrTXpsbFNtN3paUzNYcmVnQTdEak5hVVlRcXdJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQlFVQUE0R0JBTE0ydkdDaVEvdm0rYTZ2NDArVlgyemRxSEEyUS8xdkYxaWJReko1NE1KQ09WV3ZzK3ZRWGZaRmhkbTBPUE0ySXJEVTdvcXZLUHFQNnhPQWVKSzZIMHlQN000WUwzZmF0U3ZJWW1tZnlYQzlrdDNTdnovTnlySHpQaFVuSjB5ZS9zVVNYeG56UXh3Y20vOVB3QXFyUWFBM1FwUWtINTd5YkYvT29yeVBlKzJoPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1scDpTdGF0dXM+PHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgVmVyc2lvbj0iMi4wIiBJRD0icGZ4OTUxNmIwZjMtNDUzNi0xMGY2LWM2ZmEtOWRkNTIzZTE0OThjIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDYtMDRUMDI6MjI6MDJaIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9hcHAub25lbG9naW4uY29tL3NhbWwyPC9zYW1sOklzc3Vlcj48c2FtbDpTdWJqZWN0PjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMzAtMDYtMDRUMDI6Mjc6MDJaIiBSZWNpcGllbnQ9InJlY2lwaWVudCIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjxzYW1sOkVuY3J5cHRlZElEPjx4ZW5jOkVuY3J5cHRlZERhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIiB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNFbGVtZW50Ij48eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjYWVzMTI4LWNiYyIvPjxkc2lnOktleUluZm8geG1sbnM6ZHNpZz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PHhlbmM6RW5jcnlwdGVkS2V5Pjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNyc2EtMV81Ii8+PHhlbmM6Q2lwaGVyRGF0YT48eGVuYzpDaXBoZXJWYWx1ZT5ZUkdFZGF2dWpSNlYwNUZsWERHbmxCK1VUWTFjak9DallkYlhKN2JBZHFURWxDTyt1eHl0aytnMWVTTGVuczhJcjlZaVBNNUorUWU5cXo0TkdORXdyNjV6aDM5L0ZJVXNMQ3BhaXQ3QjZXM2lFcmR4aVUrSUN1cUw3TCtNSmlGVHZiVG90NVdleWZvVkFnSE94Z1BodDRONlZSL3BhYzRDdFZEQ0ZBbDlEMjA9PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9kc2lnOktleUluZm8+DQogICA8eGVuYzpDaXBoZXJEYXRhPg0KICAgICAgPHhlbmM6Q2lwaGVyVmFsdWU+dFdQZEV1dXZmSjh3WVBhOFVUQTRvR2htRENQTjFhQzVkUUFEN0g5SkhWQm5VS3Y0UkljNEQ3SnVJem12bXlyalZGWmRGNW15K3cvUGd3dWlOVGdpOUxid01iSW5adW1HbDhlSndFblBaVXBPQ0w1dDNXbEdKbU85OVVNejZQUVNLeGlGSU1DYzcrQXlRQmpjdTEzaUxWeU5TbFQyWDMxRXBOaW5jQ3FzSldvPTwveGVuYzpDaXBoZXJWYWx1ZT4NCiAgIDwveGVuYzpDaXBoZXJEYXRhPg0KPC94ZW5jOkVuY3J5cHRlZERhdGE+PC9zYW1sOkVuY3J5cHRlZElEPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDExLTA2LTA0VDAyOjE3OjAyWiIgTm90T25PckFmdGVyPSIyMDMwLTA2LTA0VDAyOjI3OjAyWiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT5odHRwczovL3NvbWVvbmUuZXhhbXBsZS5jb20vYXVkaWVuY2U8L3NhbWw6QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sOkNvbmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE0LTA2LTA0VDAyOjIyOjAyWiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAzMC0wNi0wNVQwMjoyMjowMloiIFNlc3Npb25JbmRleD0iXzE2ZjU3MGZiYzAzMTUwMDdhMDM1NWRmZWE2YjNjNDZjIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==' }
      let(:raw_xml) { Base64.decode64(encoded) }
      let(:encrypted_node) do
        document.at_xpath(
          '/samlp:Response/saml:Assertion/saml:Subject/saml:EncryptedID/xmlenc:EncryptedData',
          'xmlenc' => 'http://www.w3.org/2001/04/xmlenc#',
          'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
          'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol'
        )
      end
      let(:cipher_registry) do
        Xml::Kit::Crypto.cipher_registry do |algorithm, key|
          if algorithm == 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
            Xml::Kit::Crypto::SymmetricCipher.new(algorithm, key, 0)
          else
            Xml::Kit::Crypto.cipher_for(algorithm, key)
          end
        end
      end

      specify do
        expect(subject.decrypt_node(encrypted_node).to_s).to eql('<saml:nameid format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test@onelogin.com</saml:nameid>')
      end
    end
  end
end

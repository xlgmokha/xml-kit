# Xml::Kit

[![Build Status](https://github.com/xlgmokha/xml-kit/workflows/ci/badge.svg)](https://github.com/xlgmokha/xml-kit/actions)
[![Gem Version](https://badge.fury.io/rb/xml-kit.svg)](https://rubygems.org/gems/xml-kit)

Xml::Kit is a toolkit for working with XML. It supports adding [XML Digital Signatures](https://www.w3.org/TR/xmldsig-core/)
and [XML Encryption](https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'xml-kit'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install xml-kit

## Usage

```builder
# ./templates/item.builder

xml.instruct!
xml.Item ID: id do
  signature_for reference_id: id, xml: xml
  xml.Encrypted do
    encrypt_data_for xml: xml do |encrypted_xml|
      encrypted_xml.EncryptMe do
        encrypted_xml.Secret "secret"
      end
    end
  end
end
```

```ruby
require 'xml/kit'

class Item
  include ::Xml::Kit::Templatable

  attr_reader :id

  def initialize(signing_key_pair, encryption_certificate)
    @id = ::Xml::Kit::Id.generate
    sign_with(signing_key_pair)
    encrypt_with(encryption_certificate)
  end

  def template_path
    current_path = File.expand_path(File.dirname(__FILE__))
    File.join(current_path, "./templates/item.builder")
  end
end

signing_key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
encryption_certificate = ::Xml::Kit::KeyPair.generate(use: :encryption).certificate
puts Item.new(signing_key_pair, encryption_certificate).to_xml
```

This will produce something like the following:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Item ID="_de3f6209-f842-400f-b1f7-85159aa90299">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#_de3f6209-f842-400f-b1f7-85159aa90299">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <DigestValue>3cH13yM8oR0sgWbhAx0mo536KMJDkVBynbPo7ehwJPE=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>ZCSx4dad704jz0Z6rCMsnOs/oyVH3YBeEF9wtk2UFmWBW+VfhoBKw7N50GnzmAGCHyI6zajRPdff5i6UMDz3fOzh7rlROnqW0TXoG77xPiIfqJswCKE/4LzzBLrEHVbdUz90U8n0M1Ahbesrt+pbf/NkJghpvDhJW+w6oho7dyU6k57C5D//kTaSb7DvKte3a7/o8xWvPRztQhYekK+RyWjK9k/lU4WEXk5rGbx+QrD9rgIXBQOdcSjOtUosZJADz7uFod6AWRak246U62Xahz8JxE/1N22LhZY9whvB7s+c76f1Uv44NtF87D0P8UXs0TVx2jsnhEwLsT7DPQ6jDg==</SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIDQTCCAimgAwIBAgIBADANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJDQTEQMA4GA1UECAwHQWxiZXJ0YTEQMA4GA1UEBwwHQ2FsZ2FyeTEPMA0GA1UECgwGWG1sS2l0MQ8wDQYDVQQLDAZYbWxLaXQxDzANBgNVBAMMBlhtbEtpdDAeFw0xNzEyMzAxOTM1MjZaFw0xODAxMjkwNzAwMDBaMGQxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdBbGJlcnRhMRAwDgYDVQQHDAdDYWxnYXJ5MQ8wDQYDVQQKDAZYbWxLaXQxDzANBgNVBAsMBlhtbEtpdDEPMA0GA1UEAwwGWG1sS2l0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8yvaY1zvqiSTpDc0vFgS00N0R05ytanViNy0YrcAvLH2njvLOYi8e5lWAjCUzoWTe6FMJQySIHuzr9NvZztlQBp5tydmxDsOFQ3DrBhiqtyafdCd5s8OQz1CekavgToTOm5VdZEWLD7HSCFvHXeuiS/zwEh4yYpJBAERtsSaYxT7L1wNggxc6F6UEfF1vwrGxMNH/OUi4okeS773esXeRlP5fHyMUvVC70KHauSYt/kjNR8/WuZBOY8/kFv3XiErf0PNSAYhyGHozabv8hJ2Bho0+HR12P6Xv+qKXFlDnMeAOHy23eShuUpCEBaEPAG4o8w4g/lrn0nJ+e9XrYaNQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCWybi6buMD75KBCcyd5aRtSKavYoDaZlzuohKh4z1HEzHS/fbpbxVQOrfXtuawZjNxcn62LFIe/w68EImzYkAss8LKojRcaKnIeF1/3Pzo6qfnmFpaecfYvX3ZTtw9JPOd4chy2X2WFAUMRscjSvjNvTBzFOXg60F0UMDnWOWMbc5Di/aZD8r2s/RDE3QxcUou8QhBMc2nYw77mQsXBnWmBeUA2aGP8OG/fOgtBKkZnNF8gx7wuodbYSmKAfFGx8+CGtnkwNr4/hXgd1qg5KmsAx+9VYozCjGKSkVUIqC5khy6N+1Pb5jMKrMQ+QU9zGhylWoJ2jiK65hzUUVUESIB</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
  <Encrypted>
    <EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">
          <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <CipherData>
            <CipherValue>rBJwm+gmL6eUHBZDXs2swIL3DiZ+MfmBPpM52eF0RWFtZv/gutY02KlsFLlmjc+DO7X5p9l1Br67FjGJrTdfSSqHf35cS1cioyaKLtgniSrD7Hf9d8qIuWt56dLWjmCi21cePMJHhNiFe5yRjFHNp5LZ9dX5hvNXjbn0+p90fj8zlO2TWZv9atooON3BaYGCezZlmG0bWyEmloqKHiGjqaKtkdeSKJDzoo/AvubDEgz56rinCpw26rEOg8BBd/KNfSXyDUifOOzXmn6myq+8+W/FFQ+6y+5SgtsbONRCqe2cKkNi3fYhilwLxWCaXFjONimEOkeG03yR5QnWhzEOpw==</CipherValue>
          </CipherData>
        </EncryptedKey>
      </KeyInfo>
      <CipherData>
        <CipherValue>45rM0phzM/S/vpiq8Ev+uQZ6WL5qZ8av0UDVzWAlHn6Qr7zWYjHea+NF94lKpvmTPWQDEnfv2UW8l0VdCLc+51zHjluRE/xJh31Gk3rVuRJtLioSge/N9UM45g901rE9</CipherValue>
      </CipherData>
    </EncryptedData>
  </Encrypted>
</Item>
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/xlgmokha/xml-kit.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

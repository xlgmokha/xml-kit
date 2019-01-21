# frozen_string_literal: true

class Soap
  class HeaderKeyInfo
    include ::Xml::Kit::Templatable
    attr_accessor :template_path

    def initialize(uri:)
      @template_path = File.join(__dir__, '../fixtures/soap_header_key_info.builder')
    end
  end

  include ::Xml::Kit::Templatable

  attr_reader :id, :signing_key_pair, :encryption_key_pair
  attr_accessor :template_path

  def initialize
    @id = ::Xml::Kit::Id.generate
    @signing_key_pair = ::Xml::Kit::KeyPair.generate(use: :signing)
    @embed_signature = false
    @encrypt = true
    @encryption_key_pair = ::Xml::Kit::KeyPair.generate(use: :encryption)
    @encryption_certificate = @encryption_key_pair.certificate
    @template_path = File.join(__dir__, '../fixtures/soap.builder')
  end

  def key_id
    'EK-E2C32E59F27A1320A215468956686717'
  end

  def header_key_info
    HeaderKeyInfo.new(uri: key_id)
  end

  def body_key_info
    ::Xml::Kit::ExternalKeyInfo.new(uri: key_id)
  end
end

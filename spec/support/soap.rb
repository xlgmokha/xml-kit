# frozen_string_literal: true

class Soap
  include ::Xml::Kit::Templatable

  attr_reader :id, :encryption_key_pair
  attr_accessor :template_path

  def initialize
    @id = ::Xml::Kit::Id.generate
    @embed_signature = false
    @encrypt = true
    @encryption_key_pair = ::Xml::Kit::KeyPair.generate(use: :encryption)
    @encryption_certificate = @encryption_key_pair.certificate
    @template_path = File.join(__dir__, '../fixtures/soap.builder')
  end

  def symmetric_key
    symmetric_cipher.key
  end

  def key_id
    'EK-E2C32E59F27A1320A215468956686717'
  end

  def body_key_info
    ::Xml::Kit::KeyInfo.new do |x|
      x.retrieval_method.uri = key_id
    end
  end
end

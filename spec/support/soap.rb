# frozen_string_literal: true

class Soap
  include ::Xml::Kit::Templatable

  attr_reader :id
  attr_accessor :template_path

  def initialize(certificate)
    @id = ::Xml::Kit::Id.generate
    @template_path = File.join(__dir__, '../fixtures/soap.builder')
    encrypt_with(certificate)
  end

  def key_id
    'EK-E2C32E59F27A1320A215468956686717'
  end

  def key_info
    ::Xml::Kit::KeyInfo.new do |x|
      x.retrieval_method.uri = key_id
    end
  end
end
